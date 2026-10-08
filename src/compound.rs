//! Compound files (OLE, Microsoft's MS-CFB): a small file system in a
//! file. Jump lists (`*.automaticDestinations-ms`) are one, as are Office
//! 97–2003 documents, MSI packages and `Thumbs.db`.
//!
//! A 512-byte header, then sectors (512 or 4,096 bytes) chained by a file
//! allocation table; a directory of 128-byte entries (a red-black tree by
//! name, read here as a flat list); streams smaller than the cutoff (4,096
//! bytes) live in 64-byte mini sectors inside the root entry's stream.
//! Every chain is bounded: a looping or truncated table is an error.

use core::fmt;

use crate::{u16_at, u32_at, u64_at};

const SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const END_OF_CHAIN: u32 = 0xffff_fffe;
const FREE: u32 = 0xffff_ffff;
const NO_STREAM: u32 = 0xffff_ffff;
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
    /// Modification time (FILETIME; 0 when not recorded).
    pub modified: u64,
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
        };
        let directory = file.chain(directory_start, None)?;
        for raw in directory.chunks_exact(128) {
            let kind = raw[66];
            if kind == 0 {
                continue;
            }
            let name_len = usize::from(u16_at(raw, 64).unwrap_or(0)).min(64);
            let units: Vec<u16> = raw[..name_len.saturating_sub(2)]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            file.entries.push(Entry {
                name: String::from_utf16_lossy(&units),
                kind,
                start: u32_at(raw, 116).unwrap_or(END_OF_CHAIN),
                // Version 3 files keep only the low 32 bits meaningful.
                size: if shift == 9 {
                    u64::from(u32_at(raw, 120).unwrap_or(0))
                } else {
                    u64_at(raw, 120).unwrap_or(0)
                },
                modified: u64_at(raw, 108).unwrap_or(0),
            });
        }
        let root = file
            .entries
            .iter()
            .find(|e| e.kind == 5)
            .cloned()
            .ok_or_else(|| error("no root entry"))?;
        if root.start < END_OF_CHAIN && root.size > 0 {
            file.mini_stream = file.chain(root.start, Some(root.size))?;
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

    /// The stream named `name`, if there is one.
    ///
    /// # Errors
    /// When its chain is damaged.
    pub fn stream(&self, name: &str) -> Result<Option<Vec<u8>>, Error> {
        let Some(entry) = self.entries.iter().find(|e| e.kind == 2 && e.name == name) else {
            return Ok(None);
        };
        if entry.size == 0 || entry.start == NO_STREAM {
            return Ok(Some(Vec::new()));
        }
        if entry.size < self.cutoff {
            self.mini_chain(entry.start, entry.size).map(Some)
        } else {
            self.chain(entry.start, Some(entry.size)).map(Some)
        }
    }
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

    #[test]
    fn a_sector_past_the_end_is_an_error() {
        let data = [0u8; 1024];
        assert_eq!(sector_bytes(&data, 512, 0).map(<[u8]>::len), Ok(512));
        assert!(sector_bytes(&data, 512, 1).is_err());
        assert!(sector_bytes(&data, 512, u32::MAX).is_err());
    }
}
