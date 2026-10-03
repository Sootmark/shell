//! Jump lists against Eric Zimmerman's JLECmd (its output in
//! `tests/fixtures/oracle/`), on his MIT test set (automatic jump lists
//! from Windows 7, 8.0, 8.1 and 10), plaso's Apache-2.0 test data
//! (automatic and custom) and a synthetic custom one: every `DestList`
//! column, and the link columns of each entry.
//!
//! JLECmd names only the first category of a custom jump list; later
//! ones are checked against their bytes by hand.

mod common;

use std::collections::HashMap;
use std::fs;

use common::{fixtures, path_agrees, records, when};
use shell::jumplist::{self, Destination, Kind};
use shell::lnk::Link;

const FILES: [&str; 8] = [
    "Win10/7e4dca80246863e3.automaticDestinations-ms",
    "Win10/f01b4d95cf55d32a.automaticDestinations-ms",
    "Win10/5f7b5f1e01b83767.automaticDestinations-ms",
    "Win7/1b4dd67f29cb1962.automaticDestinations-ms",
    "Win80/f01b4d95cf55d32a.automaticDestinations-ms",
    "Win81/f01b4d95cf55d32a.automaticDestinations-ms",
    "plaso/1b4dd67f29cb1962.automaticDestinations-ms",
    "plaso/9d1f905ce5044aee.automaticDestinations-ms",
];

const CUSTOM: [&str; 3] = [
    "plaso/368d807282ccde9d.customDestinations-ms",
    "plaso/5afe4de1b92fc382.customDestinations-ms",
    "synthetic/ccba5a5986c77e43.customDestinations-ms",
];

/// A GUID as JLECmd prints it: lowercase, no braces.
fn bare(guid: &str) -> String {
    guid.trim_matches(['{', '}']).to_ascii_lowercase()
}

fn link_columns(link: &Link) -> Vec<(&'static str, String)> {
    let tracker = link.tracker.as_ref();
    vec![
        ("TargetCreated", when(link.created)),
        ("TargetModified", when(link.modified)),
        ("TargetAccessed", when(link.accessed)),
        ("FileSize", link.size.to_string()),
        ("LocalPath", link.local_path.clone()),
        ("Arguments", link.arguments.clone()),
        (
            "MachineID",
            tracker.map_or(String::new(), |t| t.machine_id.clone()),
        ),
        (
            "MachineMACAddress",
            tracker.map_or(String::new(), |t| t.mac.clone()),
        ),
    ]
}

fn check_link(link: &Link, row: &HashMap<String, String>, at: &str) {
    for (column, value) in link_columns(link) {
        assert_eq!(&value, &row[column], "{at}: {column}");
    }
    let target = link.target_path();
    assert!(
        path_agrees(&row["TargetIDAbsolutePath"], &target),
        "{at}: {} vs {target}",
        row["TargetIDAbsolutePath"]
    );
}

fn oracle(name: &str) -> HashMap<String, Vec<HashMap<String, String>>> {
    let mut by_file: HashMap<String, Vec<_>> = HashMap::new();
    for row in records(&fs::read_to_string(fixtures().join("oracle").join(name)).unwrap()) {
        by_file
            .entry(row["SourceFile"].clone())
            .or_default()
            .push(row);
    }
    by_file
}

fn columns(d: &Destination, version: u32) -> Vec<(&'static str, String)> {
    vec![
        ("EntryNumber", d.entry.to_string()),
        ("DestListVersion", version.to_string()),
        ("LastModified", when(d.last_used)),
        ("CreationTime", when(d.droid_created)),
        ("Hostname", d.hostname.clone()),
        ("MacAddress", d.mac.clone()),
        ("InteractionCount", d.access_count.unwrap_or(0).to_string()),
        (
            "PinStatus",
            if d.pin.is_some() { "True" } else { "False" }.to_owned(),
        ),
        ("FileDroid", bare(&d.file_droid)),
        ("VolumeDroid", bare(&d.volume_droid)),
        ("FileBirthDroid", bare(&d.file_birth_droid)),
        ("VolumeBirthDroid", bare(&d.volume_birth_droid)),
    ]
}

#[test]
fn automatic_matches_jlecmd() {
    let mut by_file = oracle("JLECmd.csv");
    let mut checked = 0;
    for file in FILES {
        let data = fs::read(fixtures().join("jumplist").join(file)).unwrap();
        let list = jumplist::automatic(&data).unwrap();
        assert!(list.problems.is_empty(), "{file}: {:?}", list.problems);
        let rows = by_file.remove(file).unwrap_or_default();
        assert_eq!(list.destinations.len(), rows.len(), "{file}");
        for row in rows {
            // JLECmd numbers entries most recent first, which is stream order.
            let at = format!("{file} MRU {}", row["MRU"]);
            let d = &list.destinations[row["MRU"].parse::<usize>().unwrap()];
            for (column, value) in columns(d, list.version) {
                assert_eq!(&value, &row[column], "{at}: {column}");
            }
            // JLECmd appends what it resolves the path to (`… ==> …`).
            let path = row["Path"].split(" ==> ").next().unwrap();
            assert_eq!(d.path, path, "{at}: Path");
            check_link(d.link.as_ref().unwrap(), &row, &at);
            checked += 1;
        }
    }
    assert!(by_file.is_empty(), "files not tested: {:?}", by_file.keys());
    assert_eq!(checked, 31);
}

#[test]
fn custom_matches_jlecmd() {
    let mut by_file = oracle("JLECmd-custom.csv");
    let mut checked = 0;
    for file in CUSTOM {
        let list = jumplist::custom(&fs::read(fixtures().join("jumplist").join(file)).unwrap());
        assert!(list.problems.is_empty(), "{file}: {:?}", list.problems);
        let links: Vec<(&Kind, &Link)> = list
            .categories
            .iter()
            .flat_map(|c| c.links.iter().map(move |l| (&c.kind, l)))
            .collect();
        let rows = by_file.remove(file).unwrap();
        assert_eq!(links.len(), rows.len(), "{file}");
        for (i, (row, (kind, link))) in rows.iter().zip(links).enumerate() {
            let at = format!("{file} link {i}");
            if !row["EntryName"].is_empty() {
                assert_eq!(kind, &Kind::Custom(row["EntryName"].clone()), "{at}");
            }
            check_link(link, row, &at);
            checked += 1;
        }
    }
    assert!(by_file.is_empty(), "files not tested: {:?}", by_file.keys());
    assert_eq!(checked, 17);
}

#[test]
fn custom_categories() {
    let kinds = |file: &str| -> Vec<(Kind, usize)> {
        let data = fs::read(fixtures().join("jumplist").join(file)).unwrap();
        jumplist::custom(&data)
            .categories
            .into_iter()
            .map(|c| (c.kind, c.links.len()))
            .collect()
    };
    let named = |name: &str| Kind::Custom(name.to_owned());
    assert_eq!(
        kinds(CUSTOM[0]),
        [
            (named("My Category 1"), 1),
            (Kind::Known(1), 0),
            (Kind::Tasks, 1),
            (named("My Category 2"), 1),
            (Kind::Known(2), 0),
        ]
    );
    assert_eq!(kinds(CUSTOM[1]), [(Kind::Tasks, 9)]);
    assert_eq!(
        kinds(CUSTOM[2]),
        [
            (named("Most visited"), 2),
            (named("Recently closed"), 1),
            (Kind::Tasks, 2),
        ]
    );
    // An empty list: a header and no categories.
    let empty =
        fs::read(fixtures().join("jumplist/plaso/c98dce577f884ef8.customDestinations-ms")).unwrap();
    let empty = jumplist::custom(&empty);
    assert!(empty.categories.is_empty() && empty.problems.is_empty());
}

mod garbage {
    use proptest::prelude::*;

    fn damaged(file: &str, flips: Vec<(usize, u8)>, cut: usize) -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/jumplist/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut data = std::fs::read(path).unwrap();
        for (at, byte) in flips {
            let len = data.len();
            data[at % len] = byte;
        }
        data.truncate(cut % (data.len() + 1));
        data
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_000))]

        /// A real jump list corrupted anywhere (its compound file tables,
        /// directory, `DestList` or links), or truncated: parsed or
        /// refused, never a panic.
        #[test]
        fn damaged_automatic_lists_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40), cut in any::<usize>()) {
            let data = damaged("Win10/f01b4d95cf55d32a.automaticDestinations-ms", flips, cut);
            if let Ok(file) = shell::compound::CompoundFile::parse(&data) {
                for entry in &file.entries {
                    let _ = file.stream(&entry.name);
                }
            }
            let _ = shell::jumplist::automatic(&data);
        }

        #[test]
        fn damaged_custom_lists_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40), cut in any::<usize>()) {
            let data = damaged("plaso/368d807282ccde9d.customDestinations-ms", flips, cut);
            let _ = shell::jumplist::custom(&data);
        }

        /// Any bytes at all.
        #[test]
        fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = shell::jumplist::automatic(&data);
            let _ = shell::jumplist::custom(&data);
        }
    }
}

/// Header counts far beyond the file: refused or read within bounds, not
/// allocated.
#[test]
fn huge_header_counts_are_bounded() {
    let mut data =
        fs::read(fixtures().join("jumplist/Win7/1b4dd67f29cb1962.automaticDestinations-ms"))
            .unwrap();
    for at in [44, 72] {
        data[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    }
    let _ = jumplist::automatic(&data);
    let mut custom =
        fs::read(fixtures().join("jumplist/plaso/368d807282ccde9d.customDestinations-ms")).unwrap();
    custom[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(jumplist::custom(&custom).categories.len(), 5);
}
