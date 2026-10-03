//! Windows shell items: how Explorer names a place (a drive, a folder, a
//! file, a control panel page), in ShellBags, LNK files and jump lists.
//!
//! Written from libyal's "Windows Shell Item format". An item list is a
//! run of items, each prefixed by its size, ended by a zero size. The
//! item's class (its third byte) says what it is; file entries carry a
//! short name, FAT times and, in a `BEEF0004` extension block, the long
//! name, creation and access times and the NTFS file reference.

use crate::{u16_at, u32_at, u64_at};

/// What an item is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A root folder, by class identifier (This PC, Control Panel, …).
    RootFolder,
    /// A drive (`C:`).
    Volume,
    /// A folder on a file system.
    Directory,
    /// A file.
    File,
    /// A network location (`\\server\share`).
    Network,
    /// A control panel page, by class identifier.
    ControlPanel,
    /// A control panel category (System and Security, …).
    ControlPanelCategory,
    /// A folder under the user's profile ("Users Files" delegate).
    UsersFilesFolder,
    /// A URI (an FTP site, …).
    Uri,
    /// A view with its own properties ("Users property view": control
    /// panel pages and search results), named by its display name.
    PropertyView,
    /// An item whose class this parser doesn't know: its class byte.
    Other(u8),
}

/// A decoded item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Its class byte.
    pub class: u8,
    /// What it is.
    pub kind: Kind,
    /// Its name as Explorer would show it: a folder's long name, a drive
    /// letter, a GUID in braces when nothing better is known.
    pub name: String,
    /// A class identifier it refers to, when it has one.
    pub guid: Option<String>,
    /// Modification time (FAT, as seconds since 1970, UTC as recorded).
    pub modified: Option<i64>,
    /// Creation time (FAT; extension block).
    pub created: Option<i64>,
    /// Access time (FAT; extension block).
    pub accessed: Option<i64>,
    /// NTFS file reference: MFT entry and sequence number.
    pub mft: Option<(u64, u16)>,
    /// Extension blocks found.
    pub extension_blocks: usize,
}

/// `{00000000-0000-0000-0000-000000000000}` from its 16 bytes.
#[must_use]
pub fn guid(b: &[u8]) -> Option<String> {
    let b = b.get(..16)?;
    Some(format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    ))
}

/// A version 1 GUID's timestamp (FILETIME) and node (a MAC address,
/// `00:15:5d:01:6d:02`): when and on which machine it was made, as
/// distributed link tracking identifiers record.
#[must_use]
pub fn guid_v1(b: &[u8]) -> Option<(u64, String)> {
    let b = b.get(..16)?;
    let time_low = u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let time_mid = u64::from(u16::from_le_bytes([b[4], b[5]]));
    let time_hi = u64::from(u16::from_le_bytes([b[6], b[7]]) & 0x0fff);
    let uuid_time = (time_hi << 48) | (time_mid << 32) | time_low;
    // 1582-10-15 (the GUID epoch) to 1601-01-01, in 100 ns.
    let filetime = uuid_time.checked_sub(5_748_192_000_000_000)?;
    let mac = b[10..16]
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    Some((filetime, mac))
}

/// A FAT date and time (date first, as stored) as seconds since 1970;
/// `None` when unset or impossible.
#[must_use]
pub fn fat_time(bytes: &[u8]) -> Option<i64> {
    let date = i64::from(u16_at(bytes, 0)?);
    let time = i64::from(u16_at(bytes, 2)?);
    if date == 0 {
        return None;
    }
    let (day, month, year) = (date & 0x1f, (date >> 5) & 0x0f, 1980 + (date >> 9));
    let (sec, min, hour) = ((time & 0x1f) * 2, (time >> 5) & 0x3f, time >> 11);
    if !(1..=31).contains(&day) || !(1..=12).contains(&month) || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3_600 + min * 60 + sec)
}

fn ascii_until_nul(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| char::from(b))
        .collect()
}

fn utf16_until_nul(bytes: &[u8]) -> (String, usize) {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    let len = units.len();
    (String::from_utf16_lossy(&units), 2 * len + 2)
}

/// The items of a list (each without its size prefix).
#[must_use]
pub fn items(list: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(size) = u16_at(list, at).map(usize::from) {
        if size < 2 {
            break;
        }
        let Some(item) = list.get(at..at + size) else {
            break;
        };
        out.push(item);
        at += size;
    }
    out
}

/// Decode one item (with its size prefix, as [`items`] returns it).
#[must_use]
pub fn decode(item: &[u8]) -> Item {
    let class = item.get(2).copied().unwrap_or(0);
    let mut out = Item {
        class,
        kind: Kind::Other(class),
        name: String::new(),
        guid: None,
        modified: None,
        created: None,
        accessed: None,
        mft: None,
        extension_blocks: 0,
    };
    match class {
        // A root folder (0x1F), or a known folder under This PC (0x2E:
        // Downloads, …), by identifier.
        0x1f | 0x2e => {
            out.kind = Kind::RootFolder;
            out.guid = guid(item.get(4..).unwrap_or_default());
            out.name = out
                .guid
                .as_deref()
                .and_then(root_folder)
                .unwrap_or_default()
                .to_owned();
            extension_blocks(item, 20, &mut out);
        }
        0x20..=0x2f => {
            out.kind = Kind::Volume;
            ascii_until_nul(item.get(3..).unwrap_or_default())
                .trim_end_matches('\\')
                .clone_into(&mut out.name);
        }
        // File entries; some writers set the class's high bit (0xB1).
        c if c & 0x70 == 0x30 && c != 0x71 && c != 0x74 => file_entry(item, &mut out),
        0x41..=0x4f | 0xc3 => {
            out.kind = Kind::Network;
            out.name = ascii_until_nul(item.get(5..).unwrap_or_default());
        }
        0x61 => {
            out.kind = Kind::Uri;
            out.name = uri(item);
        }
        0x71 => {
            out.kind = Kind::ControlPanel;
            out.guid = guid(item.get(14..).unwrap_or_default());
            out.name = out
                .guid
                .as_deref()
                .and_then(control_panel)
                .unwrap_or_default()
                .to_owned();
        }
        0x74 => users_files_folder(item, &mut out),
        // A known folder, by identifier (Downloads, Documents, …).
        0x00 if u32_at(item, 6) == Some(0x23fe_bbee) => {
            out.kind = Kind::RootFolder;
            out.guid = guid(item.get(14..).unwrap_or_default());
            out.name = out
                .guid
                .as_deref()
                .and_then(root_folder)
                .unwrap_or_default()
                .to_owned();
        }
        // A property store: its display name, when it has one (a library's
        // folders carry one after the 0x10141981 signature, an app under
        // Applications after `APPS`).
        0x00 if matches!(
            u32_at(item, 6),
            Some(0xbeeb_ee00 | 0x1014_1981 | 0x5350_5041)
        ) =>
        {
            out.kind = Kind::PropertyView;
            out.name = display_name(item.get(10..).unwrap_or_default()).unwrap_or_default();
        }
        0x01 if u32_at(item, 4) == Some(0x39de_2184) => {
            out.kind = Kind::ControlPanelCategory;
            control_panel_category(u32_at(item, 8).unwrap_or(u32::MAX)).clone_into(&mut out.name);
        }
        _ => {}
    }
    if out.name.is_empty() {
        if let Some(g) = &out.guid {
            out.name.clone_from(g);
        }
    }
    out
}

/// A file entry (class 0x3N: 0x1 directory, 0x2 file, 0x4 Unicode name).
fn file_entry(item: &[u8], out: &mut Item) {
    let class = out.class;
    out.kind = if class & 0x01 != 0 {
        Kind::Directory
    } else {
        Kind::File
    };
    out.modified = item.get(8..12).and_then(fat_time);
    let unicode = class & 0x04 != 0;
    let name_at = 14;
    let (short, used) = if unicode {
        utf16_until_nul(item.get(name_at..).unwrap_or_default())
    } else {
        let s = ascii_until_nul(item.get(name_at..).unwrap_or_default());
        let len = s.len() + 1;
        (s, len)
    };
    out.name = short;
    // Extension blocks start at the next even offset.
    let mut at = name_at + used;
    at += at % 2;
    extension_blocks(item, at, out);
}

/// `BEEF0004` (and other) extension blocks from `at`.
fn extension_blocks(item: &[u8], mut at: usize, out: &mut Item) {
    while let (Some(size), Some(signature)) =
        (u16_at(item, at).map(usize::from), u32_at(item, at + 4))
    {
        if size < 8 || at + size > item.len() {
            break;
        }
        out.extension_blocks += 1;
        let block = &item[at..at + size];
        if signature == 0xbeef_0004 {
            beef0004(block, out);
        }
        at += size;
    }
}

/// The file entry extension: created and accessed times, the file
/// reference (version 7 and later), and the long name.
fn beef0004(block: &[u8], out: &mut Item) {
    let version = u16_at(block, 2).unwrap_or(0);
    out.created = block.get(8..12).and_then(fat_time);
    out.accessed = block.get(12..16).and_then(fat_time);
    let name_at = match version {
        v if v >= 9 => {
            out.mft = file_reference(block);
            46
        }
        8 => {
            out.mft = file_reference(block);
            42
        }
        7 => {
            out.mft = file_reference(block);
            38
        }
        3..=6 => 20,
        _ => return,
    };
    let (long, _) = utf16_until_nul(
        block
            .get(name_at..block.len().saturating_sub(2))
            .unwrap_or_default(),
    );
    if !long.is_empty() {
        out.name = long;
    }
}

/// The NTFS file reference; zero (not on NTFS, or not recorded) is none.
fn file_reference(block: &[u8]) -> Option<(u64, u16)> {
    let raw = u64_at(block, 20).filter(|&r| r != 0)?;
    Some((raw & 0x0000_ffff_ffff_ffff, (raw >> 48) as u16))
}

/// A delegate item for a folder under the user's profile: a file entry
/// wrapped after a `CFSF` signature.
fn users_files_folder(item: &[u8], out: &mut Item) {
    out.kind = Kind::UsersFilesFolder;
    if item.get(6..10) != Some(b"CFSF") {
        return;
    }
    // The wrapped file entry, with its own size, then a terminator and
    // the delegate's two class identifiers, then its extension blocks.
    let Some(inner_size) = u16_at(item, 10).map(usize::from) else {
        return;
    };
    let Some(inner) = item.get(10..10 + inner_size) else {
        return;
    };
    let mut decoded = decode(inner);
    extension_blocks(item, 10 + inner_size + 2 + 32, &mut decoded);
    out.name = decoded.name;
    out.modified = decoded.modified;
    out.created = decoded.created;
    out.accessed = decoded.accessed;
    out.mft = decoded.mft;
    out.extension_blocks = decoded.extension_blocks;
}

/// `System.ItemNameDisplay` (FMTID `{B725F130-…}`, id 10) from a serialized
/// property store: storages (`1SPS`) of values (size, id, reserved byte,
/// then a typed value; `VT_LPWSTR` is a character count and UTF-16).
fn display_name(store: &[u8]) -> Option<String> {
    const NAME: &str = "{B725F130-47EF-101A-A5F1-02608C9EEBAC}";
    let mut at = 0;
    while let Some(size) = u32_at(store, at).map(|n| n as usize) {
        if size < 24 || at + size > store.len() {
            // Storages may be preceded by a small header: find the next.
            let next = store.get(at + 1..)?.windows(4).position(|w| w == b"1SPS")?;
            at = at + 1 + next - 4;
            continue;
        }
        let storage = &store[at..at + size];
        if storage.get(4..8) == Some(b"1SPS") && guid(storage.get(8..)?).as_deref() == Some(NAME) {
            let mut v = 24;
            while let Some(len) = u32_at(storage, v).map(|n| n as usize) {
                if len < 13 || v + len > storage.len() {
                    break;
                }
                let value = &storage[v..v + len];
                if u32_at(value, 4) == Some(10) && u16_at(value, 9) == Some(0x1f) {
                    let chars = u32_at(value, 13)? as usize;
                    let text = value.get(17..17 + 2 * chars)?;
                    return Some(utf16_until_nul(text).0);
                }
                v += len;
            }
        }
        at += size;
    }
    None
}

fn uri(item: &[u8]) -> String {
    // Data size at +4; the URI follows a fixed header, ASCII or UTF-16.
    let data = item.get(8..).unwrap_or_default();
    let unicode = item.get(3).is_some_and(|f| f & 0x80 != 0);
    if unicode {
        utf16_until_nul(data).0
    } else {
        ascii_until_nul(data)
    }
}

/// Root and known folders by class identifier, named as Eric Zimmerman's
/// tools name them (only those checked against SBECmd, LECmd or JLECmd).
fn root_folder(guid: &str) -> Option<&'static str> {
    Some(match guid {
        "{031E4825-7B94-4DC3-B131-E946B44C8DD5}" => "UsersLibraries",
        "{088E3905-0323-4B02-9826-5D99428E115F}" | "{374DE290-123F-4565-9164-39C4925E467B}" => {
            "Downloads"
        }
        "{1CF1260C-4DD0-4EBB-811F-33C572699FDE}" => "CLSID_ThisPCMyMusicRegFolder",
        "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" => "This PC",
        "{2112AB0A-C86A-4FFE-A368-0DE96E47012E}" => "MusicLibrary",
        "{22877A6D-37A1-461A-91B0-DBDA5AAEBC99}" => "Recent Places",
        "{24AD3AD4-A569-4530-98E1-AB02F9417AA8}" => "Pictures",
        "{2559A1F1-21D7-11D4-BDAF-00C04F60B9F0}" => "Help and Support",
        "{2559A1F3-21D7-11D4-BDAF-00C04F60B9F0}" => "Run...",
        "{26EE0668-A00A-44D7-9371-BEB064C98683}" => "ControlPanelHome",
        "{3080F90D-D7AD-11D9-BD98-0000947B0257}" => "Show Desktop",
        "{3080F90E-D7AD-11D9-BD98-0000947B0257}" => "Window Switcher",
        "{323CA680-C24D-4099-B94D-446DD2D7249E}" => "Favorites",
        "{33E28130-4E1E-4676-835A-98395C3BC3BB}" => "My Pictures",
        "{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}" => "CLSID_ThisPCMyPicturesRegFolder",
        "{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}" => "Music",
        "{4234D49B-0245-4DF3-B780-3893943456E1}" => "Applications",
        "{4336A54D-038B-4685-AB02-99BB52D3FB8B}" => "Samples",
        "{491E922F-5643-4AF4-A7EB-4E7A138D8174}" => "VideosLibrary",
        "{4BD8D571-6D19-48D3-BE97-422220080E43}" => "My Music",
        "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" => "ControlPanelStartupPage",
        "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" => "Shared Documents Folder (Users Files)",
        "{645FF040-5081-101B-9F08-00AA002F954E}" => "Recycle Bin",
        "{679F85CB-0220-4080-B29B-5540CC05AAB6}" => "Quick Access",
        "{7B0DB17D-9CD2-4A93-9733-46CC89022E7C}" | "{D3162B92-9365-467A-956B-92703ACA08AF}" => {
            "Documents"
        }
        "{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}" => "Saved Searches",
        "{871C5380-42A0-1069-A2EA-08002B30309D}" => "Internet Folder",
        "{A0953C92-50DC-43BF-BE83-3742FED03C9C}" => "CLSID_ThisPCMyVideosRegFolder",
        "{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}" => "CLSID_ThisPCDocumentsRegFolder",
        "{A990AE9F-A03B-4E80-94BC-9912D7504104}" => "PicturesLibrary",
        "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" => "Desktop",
        "{ED228FDF-9EA8-4870-83B1-96B02CFE0D52}" => "Games Explorer",
        "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}" => "Personal",
        _ => return None,
    })
}

/// Control panel pages by class identifier (those checked against SBECmd).
fn control_panel(guid: &str) -> Option<&'static str> {
    Some(match guid {
        "{025A5937-A6BE-4686-A844-36FE4BEC8B6D}" => "Power Options",
        "{17CD9488-1228-4B2F-88CE-4298E93E0966}" => "Default Programs",
        "{36EEF7DB-88AD-4E81-AD49-0E313F0C35F8}" => "Windows Update",
        "{60632754-C523-4B62-B45C-4172DA012619}" => "User Accounts",
        "{7007ACC7-3202-11D1-AAD2-00805FC1270E}" => "Network Connections",
        "{7B81BE6A-CE2B-4676-A29E-EB907A5126C5}" => "Programs and Features",
        "{8E908FC9-BECC-40F6-915B-F4CA0E70D03D}" => "Network and Sharing Center",
        "{96AE8D84-A250-4520-95A5-A47A7E3C548B}" => "Parental Controls",
        "{BB06C0E4-D293-4F75-8A90-CB05B6477EEE}" => "System",
        "{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" => "Security and Maintenance CPL",
        "{C555438B-3C23-4769-A71F-B6D3D9B6053A}" => "Display",
        "{ED834ED6-4B5A-4BFE-8F11-A626DCB6A921}" => "Personalization Control Panel",
        _ => return None,
    })
}

/// Control panel categories, as Windows names them.
const fn control_panel_category(id: u32) -> &'static str {
    match id {
        0 => "All Control Panel Items",
        1 => "Appearance and Personalization",
        2 => "Hardware and Sound",
        3 => "Network and Internet",
        4 => "Sound, Speech and Audio Devices",
        5 => "System and Security",
        6 => "Clock, Language, and Region",
        7 => "Ease of Access",
        8 => "Programs",
        9 => "User Accounts",
        10 => "Security Center",
        11 => "Mobile PC",
        _ => "",
    }
}
