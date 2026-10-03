//! Shell link (`.lnk`) files, from Microsoft's MS-SHLLINK: what a shortcut
//! points at, with the target's times, size and attributes as they were
//! when the link was last saved, the volume and path it was on, and the
//! machine it was made on.
//!
//! The file is a 76-byte header, then (as its flags say) the target's
//! shell item list, the link information (volume, local and network
//! paths), string data (name, relative path, working directory, arguments,
//! icon) and extra data blocks (tracker, environment variables, known
//! folder, property stores, …).

use core::fmt;

use crate::item::{self, Item};
use crate::{u16_at, u32_at, u64_at};

const HEADER_SIZE: u32 = 0x4c;
/// `{00021401-0000-0000-C000-000000000046}`.
pub(crate) const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// Link flags (MS-SHLLINK 2.1.1), in bit order.
pub const FLAGS: [&str; 27] = [
    "HasLinkTargetIDList",
    "HasLinkInfo",
    "HasName",
    "HasRelativePath",
    "HasWorkingDir",
    "HasArguments",
    "HasIconLocation",
    "IsUnicode",
    "ForceNoLinkInfo",
    "HasExpString",
    "RunInSeparateProcess",
    "Unused1",
    "HasDarwinID",
    "RunAsUser",
    "HasExpIcon",
    "NoPidlAlias",
    "Unused2",
    "RunWithShimLayer",
    "ForceNoLinkTrack",
    "EnableTargetMetadata",
    "DisableLinkPathTracking",
    "DisableKnownFolderTracking",
    "DisableKnownFolderAlias",
    "AllowLinkToLink",
    "UnaliasOnSave",
    "PreferEnvironmentPath",
    "KeepLocalIDListForUNCTarget",
];

/// Why a file couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Byte offset where it went wrong.
    pub offset: usize,
    /// What went wrong.
    pub reason: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.reason, self.offset)
    }
}

impl std::error::Error for Error {}

fn error(offset: usize, reason: impl Into<String>) -> Error {
    Error {
        offset,
        reason: reason.into(),
    }
}

/// The volume a local target was on (MS-SHLLINK 2.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    /// `DRIVE_*`: 0 unknown, 1 no root, 2 removable, 3 fixed, 4 remote,
    /// 5 CD-ROM, 6 RAM disk.
    pub drive_type: u32,
    /// Its serial number.
    pub serial: u32,
    /// Its label.
    pub label: String,
}

/// The tracker data block (MS-SHLLINK 2.5.10): the machine the link was
/// made on, and the target's distributed link tracking identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracker {
    /// The NetBIOS name of the machine.
    pub machine_id: String,
    /// The volume's identifier.
    pub volume_id: String,
    /// The file's object identifier (a version 1 GUID: its node is a MAC
    /// address, its timestamp when it was made).
    pub object_id: String,
    /// The MAC address in the object identifier: `00:15:5d:01:6d:02`.
    pub mac: String,
    /// When the object identifier was made (FILETIME).
    pub created: u64,
}

/// A parsed link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// How many bytes it occupies: through its terminal block, or all of
    /// the data when it's truncated (links follow one another in custom
    /// jump lists).
    pub length: usize,
    /// Link flags.
    pub flags: u32,
    /// The target's attributes (`FILE_ATTRIBUTE_*`).
    pub attributes: u32,
    /// The target's creation time (FILETIME; 0 when not recorded).
    pub created: u64,
    /// The target's last access time.
    pub accessed: u64,
    /// The target's last write time.
    pub modified: u64,
    /// The target's size (low 32 bits).
    pub size: u32,
    /// The target's shell items, in order.
    pub target: Vec<Item>,
    /// The target's volume.
    pub volume: Option<Volume>,
    /// The target's local path.
    pub local_path: String,
    /// The target's network share (`\\server\share`).
    pub network_path: String,
    /// The path under the network share.
    pub common_path: String,
    /// String data, when present.
    pub name: String,
    /// The target relative to the link.
    pub relative_path: String,
    /// The working directory.
    pub working_dir: String,
    /// Command line arguments.
    pub arguments: String,
    /// Icon location.
    pub icon_location: String,
    /// The target from the environment variables block (`%windir%\…`).
    pub environment_target: String,
    /// The tracker block.
    pub tracker: Option<Tracker>,
    /// Extra data blocks present, by signature, in order.
    pub blocks: Vec<u32>,
}

impl Link {
    /// The flag names set, in bit order.
    #[must_use]
    pub fn flag_names(&self) -> Vec<&'static str> {
        FLAGS
            .iter()
            .enumerate()
            .filter(|(bit, _)| self.flags & (1 << bit) != 0)
            .map(|(_, name)| *name)
            .collect()
    }

    /// The target's shell items as a path: `This PC\C:\Windows\notepad.exe`.
    #[must_use]
    pub fn target_path(&self) -> String {
        self.target
            .iter()
            .map(|i| i.name.as_str())
            .collect::<Vec<_>>()
            .join("\\")
    }

    fn has(&self, bit: u32) -> bool {
        self.flags & (1 << bit) != 0
    }
}

/// Extra data block names (MS-SHLLINK 2.5), by signature.
#[must_use]
pub const fn block_name(signature: u32) -> &'static str {
    match signature {
        0xa000_0001 => "EnvironmentVariableDataBlock",
        0xa000_0002 => "ConsoleDataBlock",
        0xa000_0003 => "TrackerDataBlock",
        0xa000_0004 => "ConsoleFEDataBlock",
        0xa000_0005 => "SpecialFolderDataBlock",
        0xa000_0006 => "DarwinDataBlock",
        0xa000_0007 => "IconEnvironmentDataBlock",
        0xa000_0008 => "ShimDataBlock",
        0xa000_0009 => "PropertyStoreDataBlock",
        0xa000_000b => "KnownFolderDataBlock",
        0xa000_000c => "VistaAndAboveIDListDataBlock",
        _ => "Unknown",
    }
}

fn ansi(bytes: &[u8]) -> String {
    // Code page text; Latin-1 keeps every byte (Windows-1252 differs only
    // in 0x80–0x9F).
    bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| char::from(b))
        .collect()
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// A NUL-terminated string at `at` in `data`, UTF-16 or code page.
fn string_at(data: &[u8], at: usize, unicode: bool) -> String {
    let rest = data.get(at..).unwrap_or_default();
    if unicode {
        utf16(rest)
    } else {
        ansi(rest)
    }
}

/// Parse a link.
///
/// # Errors
/// When it isn't a shell link (wrong header size or class identifier) or
/// its header is truncated. Damaged later sections end the parse there,
/// keeping what came before.
pub fn parse(data: &[u8]) -> Result<Link, Error> {
    if u32_at(data, 0) != Some(HEADER_SIZE) || data.get(4..20) != Some(&LINK_CLSID[..]) {
        return Err(error(0, "not a shell link (no LNK header)"));
    }
    let field = |at| u32_at(data, at).ok_or_else(|| error(at, "header truncated"));
    let time = |at| u64_at(data, at).ok_or_else(|| error(at, "header truncated"));
    let mut link = Link {
        length: data.len(),
        flags: field(20)?,
        attributes: field(24)?,
        created: time(28)?,
        accessed: time(36)?,
        modified: time(44)?,
        size: field(52)?,
        target: Vec::new(),
        volume: None,
        local_path: String::new(),
        network_path: String::new(),
        common_path: String::new(),
        name: String::new(),
        relative_path: String::new(),
        working_dir: String::new(),
        arguments: String::new(),
        icon_location: String::new(),
        environment_target: String::new(),
        tracker: None,
        blocks: Vec::new(),
    };
    let mut at = HEADER_SIZE as usize;
    if link.has(0) {
        let Some(size) = u16_at(data, at).map(usize::from) else {
            return Ok(link);
        };
        let list = data.get(at + 2..at + 2 + size).unwrap_or_default();
        link.target = item::items(list).into_iter().map(item::decode).collect();
        at += 2 + size;
    }
    if link.has(1) {
        let Some(size) = u32_at(data, at).map(|n| n as usize) else {
            return Ok(link);
        };
        if let Some(info) = data.get(at..at + size) {
            link_info(info, &mut link);
        }
        at += size;
    }
    let unicode = link.has(7);
    for bit in 2..=6 {
        if !link.has(bit) {
            continue;
        }
        let Some(chars) = u16_at(data, at).map(usize::from) else {
            return Ok(link);
        };
        let len = if unicode { chars * 2 } else { chars };
        let bytes = data.get(at + 2..at + 2 + len).unwrap_or_default();
        let text = if unicode { utf16(bytes) } else { ansi(bytes) };
        match bit {
            2 => link.name = text,
            3 => link.relative_path = text,
            4 => link.working_dir = text,
            5 => link.arguments = text,
            _ => link.icon_location = text,
        }
        at += 2 + len;
    }
    link.length = extra_data(data, at, &mut link);
    Ok(link)
}

/// LinkInfo (MS-SHLLINK 2.3): the volume and local path, or the network
/// share, with Unicode forms when the header is long enough.
fn link_info(info: &[u8], link: &mut Link) {
    let header = u32_at(info, 4).unwrap_or(0) as usize;
    let flags = u32_at(info, 8).unwrap_or(0);
    let offset = |at| u32_at(info, at).map_or(0, |n| n as usize);
    if flags & 1 != 0 {
        let volume = offset(12);
        if let Some(v) = info.get(volume..) {
            let label_at = offset_of(v, 12);
            let label = if label_at == 0x14 {
                string_at(v, offset_of(v, 16), true)
            } else {
                string_at(v, label_at, false)
            };
            link.volume = Some(Volume {
                drive_type: u32_at(v, 4).unwrap_or(0),
                serial: u32_at(v, 8).unwrap_or(0),
                label,
            });
        }
        link.local_path = if header >= 0x24 && offset(28) != 0 {
            string_at(info, offset(28), true)
        } else {
            string_at(info, offset(16), false)
        };
    }
    if flags & 2 != 0 {
        let share = offset(20);
        if let Some(n) = info.get(share..) {
            let name_at = offset_of(n, 8);
            link.network_path = if name_at > 0x14 {
                string_at(n, offset_of(n, 20), true)
            } else {
                string_at(n, name_at, false)
            };
        }
    }
    link.common_path = if header >= 0x24 && offset(32) != 0 {
        string_at(info, offset(32), true)
    } else {
        string_at(info, offset(24), false)
    };
}

fn offset_of(data: &[u8], at: usize) -> usize {
    u32_at(data, at).map_or(0, |n| n as usize)
}

/// Read the extra data blocks from `at`; returns where they end.
fn extra_data(data: &[u8], mut at: usize, link: &mut Link) -> usize {
    while let Some(size) = u32_at(data, at).map(|n| n as usize) {
        if size < 4 {
            // The terminal block.
            return at + 4;
        }
        let Some(signature) = u32_at(data, at + 4) else {
            break;
        };
        if size < 8 || at + size > data.len() {
            break;
        }
        let block = &data[at..at + size];
        link.blocks.push(signature);
        match signature {
            0xa000_0001 => {
                let unicode = utf16(block.get(268..).unwrap_or_default());
                link.environment_target = if unicode.is_empty() {
                    ansi(block.get(8..).unwrap_or_default())
                } else {
                    unicode
                };
            }
            0xa000_0003 => link.tracker = tracker(block),
            _ => {}
        }
        at += size;
    }
    // No terminal block: damaged or truncated.
    data.len()
}

/// The tracker block: machine name, then the droid (volume and object
/// identifiers) and birth droid.
fn tracker(block: &[u8]) -> Option<Tracker> {
    let machine_id = ansi(block.get(16..32)?);
    let volume_id = item::guid(block.get(32..48)?)?;
    let object = block.get(48..64)?;
    let object_id = item::guid(object)?;
    let (created, mac) = item::guid_v1(object).unwrap_or_default();
    Some(Tracker {
        machine_id,
        volume_id,
        object_id,
        mac,
        created,
    })
}
