//! LNK files against Eric Zimmerman's LECmd on his MIT test set (552
//! links from Windows XP to 10, and a damaged file; `tests/fixtures/lnk/`,
//! LECmd's output in `tests/fixtures/oracle/`): every column LECmd reports
//! about the link and its target.
//!
//! Paths must agree component by component, except where LECmd shows a
//! display form (`common::path_agrees`).

mod common;

use std::fs;

use common::{fixtures, path_agrees, records, when};
use shell::lnk;

/// LECmd's names for what the crate keeps as numbers or spec names.
fn flags(link: &lnk::Link) -> String {
    let lecmd = |name: &'static str| match name {
        "HasLinkTargetIDList" => "HasTargetIdList",
        "HasDarwinID" => "HasDarwinId",
        "KeepLocalIDListForUNCTarget" => "KeepLocalIdListForUncTarget",
        other => other,
    };
    link.flag_names()
        .into_iter()
        .map(lecmd)
        .collect::<Vec<_>>()
        .join(", ")
}

fn attributes(bits: u32) -> String {
    let names = [
        (0x1, "Readonly"),
        (0x2, "Hidden"),
        (0x4, "System"),
        (0x10, "Directory"),
        (0x20, "Archive"),
        (0x40, "Device"),
        (0x80, "Normal"),
        (0x100, "Temporary"),
        (0x200, "SparseFile"),
        (0x400, "ReparsePoint"),
        (0x800, "Compressed"),
        (0x1000, "Offline"),
        (0x2000, "NotContentIndexed"),
        (0x4000, "Encrypted"),
    ];
    let set: Vec<String> = names
        .iter()
        .filter(|(b, _)| bits & b != 0)
        .map(|(_, n)| format!("FileAttribute{n}"))
        .collect();
    if set.is_empty() {
        "0".to_owned()
    } else {
        set.join(", ")
    }
}

fn drive(volume: Option<&lnk::Volume>) -> &'static str {
    match volume.map(|v| v.drive_type) {
        None => "(None)",
        Some(2) => "Removable storage media (Floppy, USB)",
        Some(3) => "Fixed storage media (Hard drive)",
        Some(4) => "Remote storage",
        Some(5) => "CD-ROM",
        Some(_) => "other",
    }
}

#[test]
fn matches_lecmd() {
    let oracle = records(&fs::read_to_string(fixtures().join("oracle/LECmd.csv")).unwrap());
    assert_eq!(oracle.len(), 552);
    for row in &oracle {
        let file = &row["SourceFile"];
        let link = lnk::parse(&fs::read(fixtures().join("lnk").join(file)).unwrap()).unwrap();
        let volume = link.volume.as_ref();
        let tracker = link.tracker.as_ref();
        let mft = link.target.iter().rev().find_map(|i| i.mft);
        let blocks: Vec<&str> = link
            .blocks
            .iter()
            .map(|&b| match lnk::block_name(b) {
                // LECmd's spelling.
                "TrackerDataBlock" => "TrackerDataBaseBlock",
                other => other,
            })
            .collect();
        let ours = [
            ("TargetCreated", when(link.created)),
            ("TargetModified", when(link.modified)),
            ("TargetAccessed", when(link.accessed)),
            ("FileSize", link.size.to_string()),
            ("RelativePath", link.relative_path.clone()),
            ("WorkingDirectory", link.working_dir.clone()),
            ("Arguments", link.arguments.clone()),
            ("FileAttributes", attributes(link.attributes)),
            ("HeaderFlags", flags(&link)),
            ("DriveType", drive(volume).to_owned()),
            (
                "VolumeSerialNumber",
                volume.map_or(String::new(), |v| format!("{:08X}", v.serial)),
            ),
            (
                "VolumeLabel",
                volume.map_or(String::new(), |v| v.label.clone()),
            ),
            ("LocalPath", link.local_path.clone()),
            ("NetworkPath", link.network_path.clone()),
            ("CommonPath", link.common_path.clone()),
            (
                "MachineID",
                tracker.map_or(String::new(), |t| t.machine_id.clone()),
            ),
            (
                "MachineMACAddress",
                tracker.map_or(String::new(), |t| t.mac.clone()),
            ),
            (
                "TrackerCreatedOn",
                tracker.map_or(String::new(), |t| when(t.created)),
            ),
            (
                "TargetMFTEntryNumber",
                mft.map_or(String::new(), |(e, _)| format!("0x{e:X}")),
            ),
            (
                "TargetMFTSequenceNumber",
                mft.map_or(String::new(), |(_, s)| format!("0x{s:X}")),
            ),
            ("ExtraBlocksPresent", blocks.join(", ")),
        ];
        for (column, value) in ours {
            assert_eq!(&value, &row[column], "{file}: {column}");
        }
        assert!(
            path_agrees(&row["TargetIDAbsolutePath"], &link.target_path()),
            "{file}: {} vs {}",
            row["TargetIDAbsolutePath"],
            link.target_path()
        );
    }
}

#[test]
fn refuses_what_isnt_a_link() {
    let data = fs::read(fixtures().join("lnk/Bad/$I2GXWHL.lnk")).unwrap();
    assert!(lnk::parse(&data).is_err());
    assert!(lnk::parse(b"").is_err());
}

mod garbage {
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_000))]

        /// A real link corrupted anywhere, or truncated: parsed or refused,
        /// never a panic.
        #[test]
        fn damaged_links_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40), cut in any::<usize>()) {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lnk/Win10/WinHex  18.5 32-bit.lnk");
            let mut data = std::fs::read(path).unwrap();
            for (at, byte) in flips {
                let len = data.len();
                data[at % len] = byte;
            }
            data.truncate(cut % (data.len() + 1));
            let _ = shell::lnk::parse(&data);
        }
    }
}
