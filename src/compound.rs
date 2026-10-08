//! Compound files (OLE, Microsoft's MS-CFB): a small file system in a
//! file. Jump lists (`*.automaticDestinations-ms`) are one, as are Office
//! 97–2003 documents, MSI packages and `Thumbs.db`.
//!
//! A 512-byte header, then sectors (512 or 4,096 bytes) chained by a file
//! allocation table; a directory of 128-byte entries, the children of each
//! storage a red-black tree by name; streams smaller than the cutoff (4,096
//! bytes) live in 64-byte mini sectors inside the root entry's stream.
//! Every chain is bounded: a looping or truncated table is an error. The
//! tree is walked down from the root to give each entry its parent and
//! path; each entry is reached at most once, so a looping or damaged link
//! is a problem and the walk goes on.

use core::fmt;

use common::time::Ts;

use crate::{u16_at, u32_at, u64_at};

const SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const END_OF_CHAIN: u32 = 0xffff_fffe;
const FREE: u32 = 0xffff_ffff;
const NO_STREAM: u32 = 0xffff_ffff;
/// Bytes of a directory entry.
const DIRECTORY_ENTRY_SIZE: usize = 128;
/// Directory entry types.
const UNUSED: u8 = 0;
const STORAGE: u8 = 1;
const STREAM: u8 = 2;
const ROOT: u8 = 5;
/// Bytes of a mini sector.
const MINI_SECTOR_SIZE: usize = 64;

/// Why a compound file couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// What went wrong.
    pub reason: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for Error {}

fn error(reason: impl Into<String>) -> Error {
    Error {
        reason: reason.into(),
    }
}

/// A directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its name.
    pub name: String,
    /// 1 storage, 2 stream, 5 root.
    pub kind: u8,
    /// First sector of its data.
    start: u32,
    /// Its size in bytes.
    pub size: u64,
    /// When it was created: storages; `None` when not recorded, as for
    /// streams and usually the root.
    pub created: Option<Ts>,
    /// When it was last modified: storages and the root; `None` when not
    /// recorded, as for streams.
    pub modified: Option<Ts>,
    /// The storage holding it, as an index into [`CompoundFile::entries`]:
    /// `None` for the root, and for an entry the tree doesn't reach from the
    /// root.
    pub parent: Option<usize>,
    /// The names from the root's down to its own, joined by `/` (which
    /// MS-CFB forbids in names): `Root Entry/\u{5}SummaryInformation`. An
    /// entry the tree doesn't reach from the root has its name alone.
    pub path: String,
}

/// A directory entry's links, by directory entry number.
#[derive(Debug, Clone, Copy)]
struct Links {
    /// Its siblings in its storage's tree.
    left: u32,
    right: u32,
    /// The top of a storage's own tree of children.
    child: u32,
}

/// An opened compound file.
#[derive(Debug, Clone)]
pub struct CompoundFile<'a> {
    data: &'a [u8],
    sector: usize,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    mini_stream: Vec<u8>,
    cutoff: u64,
    /// Its directory entries, in directory order.
    pub entries: Vec<Entry>,
    /// Damage to the directory tree: links to missing or unused entries,
    /// entries linked twice (a loop), entries the root doesn't reach. The
    /// rest of the file still reads.
    pub problems: Vec<String>,
}

impl<'a> CompoundFile<'a> {
    /// Open a compound file.
    ///
    /// # Errors
    /// When it isn't one, or its tables or directory are damaged.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.get(..8) != Some(&SIGNATURE[..]) {
            return Err(error("not a compound file (no OLE signature)"));
        }
        let shift = u16_at(data, 30).ok_or_else(|| error("header truncated"))?;
        if shift != 9 && shift != 12 {
            return Err(error(format!("unsupported sector size 2^{shift}")));
        }
        let sector = 1_usize << shift;
        let at = |o| u32_at(data, o).ok_or_else(|| error("header truncated"));
        // No more table sectors than the file holds, whatever it claims.
        let fat_sectors = (at(44)? as usize).min(data.len() / sector);
        let directory_start = at(48)?;
        let cutoff = u64::from(at(56)?);
        let mini_fat_start = at(60)?;
        let mut difat_next = at(68)?;
        let difat_count = at(72)? as usize;
        // The FAT's own sectors: 109 listed in the header, the rest in
        // DIFAT sectors.
        let mut fat_list: Vec<u32> = (0..109).filter_map(|i| u32_at(data, 76 + 4 * i)).collect();
        for _ in 0..difat_count.min(data.len() / sector) {
            if difat_next >= END_OF_CHAIN {
                break;
            }
            let body = sector_bytes(data, sector, difat_next)?;
            let per = sector / 4 - 1;
            fat_list.extend((0..per).filter_map(|i| u32_at(body, 4 * i)));
            difat_next = u32_at(body, 4 * per).unwrap_or(END_OF_CHAIN);
        }
        let mut fat = Vec::with_capacity(fat_sectors * sector / 4);
        for &s in fat_list
            .iter()
            .filter(|&&s| s < END_OF_CHAIN)
            .take(fat_sectors)
        {
            let body = sector_bytes(data, sector, s)?;
            fat.extend((0..sector / 4).filter_map(|i| u32_at(body, 4 * i)));
        }
        let mut file = Self {
            data,
            sector,
            fat,
            mini_fat: Vec::new(),
            mini_stream: Vec::new(),
            cutoff,
            entries: Vec::new(),
            problems: Vec::new(),
        };
        let directory = file.chain(directory_start, None)?;
        // Directory entry number to index in `entries`, and each entry's links.
        let mut indexes = Vec::new();
        let mut links = Vec::new();
        for raw in directory.chunks_exact(DIRECTORY_ENTRY_SIZE) {
            let kind = raw[66];
            if kind == UNUSED {
                indexes.push(None);
                continue;
            }
            indexes.push(Some(file.entries.len()));
            let link = |at| u32_at(raw, at).unwrap_or(NO_STREAM);
            links.push(Links {
                left: link(68),
                right: link(72),
                child: link(76),
            });
            let name_len = usize::from(u16_at(raw, 64).unwrap_or(0)).min(64);
            let units: Vec<u16> = raw[..name_len.saturating_sub(2)]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16_lossy(&units);
            file.entries.push(Entry {
                path: name.clone(),
                name,
                kind,
                start: u32_at(raw, 116).unwrap_or(END_OF_CHAIN),
                // Version 3 files keep only the low 32 bits meaningful.
                size: if shift == 9 {
                    u64::from(u32_at(raw, 120).unwrap_or(0))
                } else {
                    u64_at(raw, 120).unwrap_or(0)
                },
                created: filetime(u64_at(raw, 100).unwrap_or(0)),
                modified: filetime(u64_at(raw, 108).unwrap_or(0)),
                parent: None,
            });
        }
        let root = file
            .entries
            .iter()
            .position(|e| e.kind == ROOT)
            .ok_or_else(|| error("no root entry"))?;
        file.problems = place(&mut file.entries, &indexes, &links, root);
        let (start, size) = (file.entries[root].start, file.entries[root].size);
        if start < END_OF_CHAIN && size > 0 {
            file.mini_stream = file.chain(start, Some(size))?;
        }
        if mini_fat_start < END_OF_CHAIN {
            let raw = file.chain(mini_fat_start, None)?;
            file.mini_fat = (0..raw.len() / 4)
                .filter_map(|i| u32_at(&raw, 4 * i))
                .collect();
        }
        Ok(file)
    }

    /// Follow a sector chain from `start`, up to `size` bytes when given.
    fn chain(&self, start: u32, size: Option<u64>) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let mut current = start;
        // A chain visits each sector of the file at most once: more steps
        // mean it loops, and copying on would amplify a small file.
        let limit = self.fat.len().min(self.data.len() / self.sector) + 1;
        for _ in 0..limit {
            if current == END_OF_CHAIN || current == FREE {
                break;
            }
            out.extend_from_slice(sector_bytes(self.data, self.sector, current)?);
            if size.is_some_and(|s| out.len() as u64 >= s) {
                break;
            }
            current = *self
                .fat
                .get(current as usize)
                .ok_or_else(|| error(format!("sector {current} outside the allocation table")))?;
        }
        if current != END_OF_CHAIN
            && current != FREE
            && !size.is_some_and(|s| out.len() as u64 >= s)
        {
            return Err(error("sector chain loops"));
        }
        if let Some(size) = size {
            out.truncate(size as usize);
        }
        Ok(out)
    }

    /// Follow a mini sector chain.
    fn mini_chain(&self, start: u32, size: u64) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let mut current = start;
        let limit = self
            .mini_fat
            .len()
            .min(self.mini_stream.len() / MINI_SECTOR_SIZE);
        for _ in 0..=limit {
            if current == END_OF_CHAIN || current == FREE || out.len() as u64 >= size {
                break;
            }
            let bytes = span(current as usize, MINI_SECTOR_SIZE)
                .and_then(|range| self.mini_stream.get(range))
                .ok_or_else(|| error(format!("mini sector {current} outside the mini stream")))?;
            out.extend_from_slice(bytes);
            current = *self
                .mini_fat
                .get(current as usize)
                .ok_or_else(|| error(format!("mini sector {current} outside the mini table")))?;
        }
        if (out.len() as u64) < size {
            return Err(error("mini stream chain ends early"));
        }
        out.truncate(size as usize);
        Ok(out)
    }

    /// The first stream named `name` in directory order, in any storage
    /// (its [`Entry::path`] tells them apart; read one with
    /// [`contents`](Self::contents)), if there is one.
    ///
    /// # Errors
    /// When its chain is damaged.
    pub fn stream(&self, name: &str) -> Result<Option<Vec<u8>>, Error> {
        self.entries
            .iter()
            .find(|e| e.kind == STREAM && e.name == name)
            .map(|entry| self.contents(entry))
            .transpose()
    }

    /// A stream's bytes (none for a storage or the root).
    ///
    /// # Errors
    /// When its chain is damaged.
    pub fn contents(&self, entry: &Entry) -> Result<Vec<u8>, Error> {
        if entry.kind != STREAM || entry.size == 0 || entry.start == NO_STREAM {
            Ok(Vec::new())
        } else if entry.size < self.cutoff {
            self.mini_chain(entry.start, entry.size)
        } else {
            self.chain(entry.start, Some(entry.size))
        }
    }
}

/// Each entry's parent and path, walking the tree down from `root`; damage
/// returned as problems. `indexes` maps directory entry numbers to indexes
/// in `entries` (`None` for unused entries); `links` follows `entries`.
/// Each entry is placed at most once, so the walk takes no more steps than
/// three per entry, whatever the links say.
fn place(
    entries: &mut [Entry],
    indexes: &[Option<usize>],
    links: &[Links],
    root: usize,
) -> Vec<String> {
    let mut problems = Vec::new();
    let mut placed = vec![false; entries.len()];
    placed[root] = true;
    let mut storages = vec![root];
    while let Some(storage) = storages.pop() {
        let mut pending = vec![links[storage].child];
        while let Some(number) = pending.pop() {
            if number == NO_STREAM {
                continue;
            }
            let Some(index) = indexes.get(number as usize).copied().flatten() else {
                problems.push(format!(
                    "{}: link to missing or unused directory entry {number}",
                    entries[storage].path
                ));
                continue;
            };
            if core::mem::replace(&mut placed[index], true) {
                problems.push(format!(
                    "{}: directory entry {number} linked twice",
                    entries[storage].path
                ));
                continue;
            }
            let path = format!("{}/{}", entries[storage].path, entries[index].name);
            let entry = &mut entries[index];
            entry.parent = Some(storage);
            entry.path = path;
            pending.extend([links[index].left, links[index].right]);
            if matches!(entry.kind, STORAGE | ROOT) {
                storages.push(index);
            }
        }
    }
    let unreached = placed.iter().filter(|&&reached| !reached).count();
    if unreached > 0 {
        problems.push(format!(
            "{unreached} of {} directory entries not reached from the root",
            entries.len()
        ));
    }
    problems
}

/// A FILETIME, `None` when zero (not recorded).
fn filetime(raw: u64) -> Option<Ts> {
    (raw != 0).then(|| Ts::from_filetime(raw))
}

/// Sector `n` (sector 0 follows the 512-byte header).
fn sector_bytes(data: &[u8], sector: usize, n: u32) -> Result<&[u8], Error> {
    let range = (n as usize)
        .checked_add(1)
        .and_then(|index| span(index, sector))
        .ok_or_else(|| error("sector number overflows"))?;
    data.get(range)
        .ok_or_else(|| error(format!("sector {n} past the end of the file")))
}

/// The bytes of block `index` of `size`-byte blocks, if its end fits in a
/// `usize` (it may not on 32-bit targets).
fn span(index: usize, size: usize) -> Option<core::ops::Range<usize>> {
    let start = index.checked_mul(size)?;
    Some(start..start.checked_add(size)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_whose_end_overflows_has_no_span() {
        assert_eq!(span(2, 512), Some(1024..1536));
        assert_eq!(span(usize::MAX / 512, 512), None);
        assert_eq!(span(usize::MAX, 1), None);
    }

    const NONE: u32 = NO_STREAM;

    fn entry(name: &str, kind: u8) -> Entry {
        Entry {
            name: name.to_owned(),
            kind,
            start: END_OF_CHAIN,
            size: 0,
            created: None,
            modified: None,
            parent: None,
            path: name.to_owned(),
        }
    }

    fn links(left: u32, right: u32, child: u32) -> Links {
        Links { left, right, child }
    }

    /// `entries` placed, one per directory entry number (none unused).
    fn placed(entries: &mut [Entry], links: &[Links]) -> Vec<String> {
        let indexes: Vec<Option<usize>> = (0..entries.len()).map(Some).collect();
        place(entries, &indexes, links, 0)
    }

    fn paths(entries: &[Entry]) -> Vec<(&str, Option<usize>)> {
        entries
            .iter()
            .map(|e| (e.path.as_str(), e.parent))
            .collect()
    }

    #[test]
    fn every_entry_gets_its_parent_and_path() {
        // Root: B (left A, right C); C is a storage holding D.
        let mut entries = [
            entry("Root Entry", ROOT),
            entry("A", STREAM),
            entry("B", STREAM),
            entry("C", STORAGE),
            entry("D", STREAM),
        ];
        let links = [
            links(NONE, NONE, 2),
            links(NONE, NONE, NONE),
            links(1, 3, NONE),
            links(NONE, NONE, 4),
            links(NONE, NONE, NONE),
        ];
        assert_eq!(placed(&mut entries, &links), Vec::<String>::new());
        assert_eq!(
            paths(&entries),
            [
                ("Root Entry", None),
                ("Root Entry/A", Some(0)),
                ("Root Entry/B", Some(0)),
                ("Root Entry/C", Some(0)),
                ("Root Entry/C/D", Some(3)),
            ]
        );
    }

    #[test]
    fn unused_entries_are_skipped_by_number() {
        // Directory entry 1 is unused: number 2 is the second entry kept.
        let mut entries = [entry("Root Entry", ROOT), entry("A", STREAM)];
        let links = [links(NONE, NONE, 2), links(NONE, NONE, NONE)];
        let problems = place(&mut entries, &[Some(0), None, Some(1)], &links, 0);
        assert_eq!(problems, Vec::<String>::new());
        assert_eq!(entries[1].path, "Root Entry/A");
    }

    #[test]
    fn a_loop_is_walked_once_and_reported() {
        // A storage whose child links back to it, and to the root.
        let mut entries = [entry("Root Entry", ROOT), entry("S", STORAGE)];
        let links = [links(NONE, NONE, 1), links(0, 1, 1)];
        assert_eq!(
            placed(&mut entries, &links),
            [
                "Root Entry: directory entry 1 linked twice",
                "Root Entry: directory entry 0 linked twice",
                "Root Entry/S: directory entry 1 linked twice",
            ]
        );
        assert_eq!(
            paths(&entries),
            [("Root Entry", None), ("Root Entry/S", Some(0))]
        );
    }

    #[test]
    fn missing_unused_and_unreached_entries_are_problems() {
        let mut entries = [
            entry("Root Entry", ROOT),
            entry("A", STREAM),
            entry("Orphan", STREAM),
        ];
        let links = [
            links(NONE, NONE, 1),
            links(7, 3, NONE),
            links(NONE, NONE, NONE),
        ];
        let indexes = [Some(0), Some(1), Some(2), None];
        assert_eq!(
            place(&mut entries, &indexes, &links, 0),
            [
                "Root Entry: link to missing or unused directory entry 3",
                "Root Entry: link to missing or unused directory entry 7",
                "1 of 3 directory entries not reached from the root",
            ]
        );
        assert_eq!(
            paths(&entries),
            [
                ("Root Entry", None),
                ("Root Entry/A", Some(0)),
                ("Orphan", None)
            ]
        );
    }

    #[test]
    fn a_stream_has_no_children() {
        let mut entries = [
            entry("Root Entry", ROOT),
            entry("A", STREAM),
            entry("B", STREAM),
        ];
        let links = [
            links(NONE, NONE, 1),
            links(NONE, NONE, 2),
            links(NONE, NONE, NONE),
        ];
        assert_eq!(
            placed(&mut entries, &links),
            ["1 of 3 directory entries not reached from the root"]
        );
    }

    #[test]
    fn a_zero_filetime_is_not_recorded() {
        assert_eq!(filetime(0), None);
        assert_eq!(
            filetime(130_131_449_897_040_000).and_then(|t| t.to_iso8601()),
            Some("2013-05-16T02:29:49.7040000Z".to_owned())
        );
    }

    #[test]
    fn a_sector_past_the_end_is_an_error() {
        let data = [0u8; 1024];
        assert_eq!(sector_bytes(&data, 512, 0).map(<[u8]>::len), Ok(512));
        assert!(sector_bytes(&data, 512, 1).is_err());
        assert!(sector_bytes(&data, 512, u32::MAX).is_err());
    }
}
