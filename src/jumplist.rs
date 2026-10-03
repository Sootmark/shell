//! Jump lists: what an application's taskbar menu offers, recently and
//! frequently used files and pinned items, per application
//! (`%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\
//! <AppID>.automaticDestinations-ms` and `…\CustomDestinations\
//! <AppID>.customDestinations-ms`).
//!
//! An automatic jump list is a compound file: a `DestList` stream (one
//! entry per item: last access, pin state, access count, the machine and
//! tracker identifiers, the path) and one LNK stream per entry, named by
//! its entry number in hexadecimal. A custom jump list is a sequence of
//! LNK records between category headers.

use crate::compound::{self, CompoundFile};
use crate::item;
use crate::lnk::{self, Link};
use crate::{u16_at, u32_at, u64_at};

/// One `DestList` entry and the link it describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// Its entry number (its LNK stream's name, in hexadecimal).
    pub entry: u32,
    /// Its position in the list as stored (the list is most recent last).
    pub position: usize,
    /// When it was last used (FILETIME).
    pub last_used: u64,
    /// Whether it's pinned, and where: `None` when not.
    pub pin: Option<u32>,
    /// How many times it was used (Windows 10 and later).
    pub access_count: Option<u32>,
    /// The machine (NetBIOS name).
    pub hostname: String,
    /// The link tracker's identifiers (empty when not recorded): the
    /// volume and the file now, and when the file was first tracked.
    pub volume_droid: String,
    /// See `volume_droid`.
    pub file_droid: String,
    /// See `volume_droid`.
    pub volume_birth_droid: String,
    /// See `volume_droid`.
    pub file_birth_droid: String,
    /// When the file's identifier was made (FILETIME; 0 when it isn't a
    /// version 1 identifier).
    pub droid_created: u64,
    /// The MAC address in it: the machine that made it.
    pub mac: String,
    /// Its path, as the list records it.
    pub path: String,
    /// Its link, when its stream is there and readable.
    pub link: Option<Link>,
}

/// A parsed automatic jump list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Automatic {
    /// `DestList` format version: 1 (Windows 7, 8), 3 or 4 (Windows 10+).
    pub version: u32,
    /// The entries, in stream order.
    pub destinations: Vec<Destination>,
    /// Entries or links that couldn't be read, and why.
    pub problems: Vec<String>,
}

/// Parse an automatic jump list.
///
/// # Errors
/// When it isn't a compound file. A missing or damaged `DestList` leaves
/// no entries and a problem.
pub fn automatic(data: &[u8]) -> Result<Automatic, compound::Error> {
    let file = CompoundFile::parse(data)?;
    let mut list = Automatic {
        version: 0,
        destinations: Vec::new(),
        problems: Vec::new(),
    };
    let dest_list = match file.stream("DestList") {
        Ok(Some(d)) if d.len() >= 32 => d,
        Ok(_) => return Ok(list),
        Err(e) => {
            list.problems.push(format!("DestList: {e}"));
            return Ok(list);
        }
    };
    list.version = u32_at(&dest_list, 0).unwrap_or(0);
    let count = u32_at(&dest_list, 4).unwrap_or(0) as usize;
    // Where the path's length sits in an entry, and what follows the path.
    let (path_at, trailer) = if list.version >= 3 {
        (128, 4)
    } else {
        (112, 0)
    };
    let mut at = 32;
    for position in 0..count {
        let Some(entry) = dest_list.get(at..) else {
            break;
        };
        let Some(chars) = u16_at(entry, path_at).map(usize::from) else {
            list.problems
                .push(format!("DestList entry {position} truncated"));
            break;
        };
        let path_bytes = entry.get(path_at + 2..path_at + 2 + 2 * chars);
        let Some(path_bytes) = path_bytes else {
            list.problems
                .push(format!("DestList entry {position} truncated"));
            break;
        };
        let units: Vec<u16> = path_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let number = u32_at(entry, 88).unwrap_or(0);
        let pin = u32_at(entry, 108).filter(|&p| p != u32::MAX);
        let link = match file.stream(&format!("{number:x}")) {
            Ok(Some(bytes)) => match lnk::parse(&bytes) {
                Ok(link) => Some(link),
                Err(e) => {
                    list.problems.push(format!("entry {number:x}: {e}"));
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                list.problems.push(format!("entry {number:x}: {e}"));
                None
            }
        };
        let (droid_created, mac) = item::guid_v1(&entry[24..40]).unwrap_or_default();
        list.destinations.push(Destination {
            entry: number,
            position,
            last_used: u64_at(entry, 100).unwrap_or(0),
            pin,
            access_count: if list.version >= 3 {
                u32_at(entry, 116)
            } else {
                None
            },
            hostname: entry[72..88]
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| char::from(b))
                .collect(),
            volume_droid: droid(&entry[8..24]),
            file_droid: droid(&entry[24..40]),
            volume_birth_droid: droid(&entry[40..56]),
            file_birth_droid: droid(&entry[56..72]),
            droid_created,
            mac,
            path: String::from_utf16_lossy(&units),
            link,
        });
        at += path_at + 2 + 2 * chars + trailer;
    }
    Ok(list)
}

/// A tracker identifier, empty when it's all zeros (not recorded).
fn droid(bytes: &[u8]) -> String {
    if bytes.iter().all(|&b| b == 0) {
        String::new()
    } else {
        item::guid(bytes).unwrap_or_default()
    }
}

/// What a custom jump list category holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// One the application named ("Most visited", "Recently closed").
    Custom(String),
    /// A category Windows fills from the automatic jump list: 1 frequent,
    /// 2 recent. It holds no links itself.
    Known(u32),
    /// The application's tasks.
    Tasks,
}

/// A custom jump list category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    /// What it is.
    pub kind: Kind,
    /// Its links, in order.
    pub links: Vec<Link>,
}

/// A parsed custom jump list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Custom {
    /// The categories, in order.
    pub categories: Vec<Category>,
    /// What couldn't be read, and why; reading stops there.
    pub problems: Vec<String>,
}

const FOOTER: u32 = 0xbabf_fbab;

/// Parse a custom jump list: a header (version, category count), then
/// each category (its type and name or identifier, then links, each after
/// the shell link class identifier), each closed by a footer.
#[must_use]
pub fn custom(data: &[u8]) -> Custom {
    let mut list = Custom {
        categories: Vec::new(),
        problems: Vec::new(),
    };
    let Some(count) = u32_at(data, 4) else {
        list.problems.push("header truncated".to_owned());
        return list;
    };
    let mut at = 12;
    for index in 0..count {
        match category(data, at) {
            Ok((category, end)) => {
                list.categories.push(category);
                at = end;
            }
            Err(reason) => {
                list.problems.push(format!("category {index}: {reason}"));
                break;
            }
        }
    }
    list
}

/// The category at `at`, and where the next one starts.
fn category(data: &[u8], mut at: usize) -> Result<(Category, usize), String> {
    let truncated = || "truncated".to_owned();
    let kind = match u32_at(data, at).ok_or_else(truncated)? {
        0 => {
            let chars = usize::from(u16_at(data, at + 4).ok_or_else(truncated)?);
            let bytes = data.get(at + 6..at + 6 + 2 * chars).ok_or_else(truncated)?;
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            at += 6 + 2 * chars;
            Kind::Custom(String::from_utf16_lossy(&units))
        }
        1 => {
            let id = u32_at(data, at + 4).ok_or_else(truncated)?;
            at += 8;
            Kind::Known(id)
        }
        2 => {
            at += 4;
            Kind::Tasks
        }
        other => return Err(format!("unknown category type {other}")),
    };
    let mut links = Vec::new();
    if !matches!(kind, Kind::Known(_)) {
        let entries = u32_at(data, at).ok_or_else(truncated)?;
        at += 4;
        for _ in 0..entries {
            if data.get(at..at + 16) != Some(&lnk::LINK_CLSID[..]) {
                return Err(format!("no shell link class identifier at {at}"));
            }
            let link =
                lnk::parse(&data[at + 16..]).map_err(|e| format!("link at {}: {e}", at + 16))?;
            at += 16 + link.length;
            links.push(link);
        }
    }
    if u32_at(data, at) != Some(FOOTER) {
        return Err(format!("no category footer at {at}"));
    }
    Ok((Category { kind, links }, at + 4))
}
