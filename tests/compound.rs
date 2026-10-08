//! Compound files' directories against olefile (BSD-licensed, run as an
//! oracle only: `tests/fixtures/oracle/olefile_tree.py` wrote
//! `olefile.tsv`): every entry's path, type, size, creation and
//! modification time, in plaso's `Document.doc` (Apache-2.0; a storage
//! inside a storage, with both times) and in the automatic jump lists.

use std::collections::BTreeSet;

use shell::compound::{CompoundFile, Entry};

/// `Document.doc` and the eight automatic jump lists.
const FILES: usize = 9;
/// 100 ns ticks from 1601-01-01 (FILETIME's epoch) to 1970-01-01.
const FILETIME_UNIX_OFFSET: i64 = 116_444_736_000_000_000;

fn fixtures(path: &str) -> String {
    format!("{}/tests/fixtures/{path}", env!("CARGO_MANIFEST_DIR"))
}

/// A path as `olefile_tree.py` writes it: characters outside printable
/// ASCII as `\u{hex}`.
fn escaped(path: &str) -> String {
    path.chars()
        .map(|c| {
            if (' '..='~').contains(&c) {
                c.to_string()
            } else {
                c.escape_unicode().to_string()
            }
        })
        .collect()
}

/// A time back to its FILETIME, 0 when not recorded.
fn filetime(time: Option<common::time::Ts>) -> i64 {
    time.map_or(0, |t| t.ticks().unwrap() + FILETIME_UNIX_OFFSET)
}

fn line(file: &str, entry: &Entry) -> String {
    format!(
        "{file}\t{}\t{}\t{}\t{}\t{}",
        escaped(&entry.path),
        entry.kind,
        entry.size,
        filetime(entry.created),
        filetime(entry.modified)
    )
}

#[test]
fn every_entry_as_olefile_reads_it() {
    let oracle = std::fs::read_to_string(fixtures("oracle/olefile.tsv")).unwrap();
    let expected: BTreeSet<String> = oracle.lines().map(str::to_owned).collect();
    let files: BTreeSet<&str> = oracle
        .lines()
        .filter_map(|line| line.split('\t').next())
        .collect();
    assert_eq!(files.len(), FILES);
    let mut got = BTreeSet::new();
    for file in files {
        let data = std::fs::read(fixtures(file)).unwrap();
        let compound = CompoundFile::parse(&data).unwrap();
        assert_eq!(compound.problems, Vec::<String>::new(), "{file}");
        got.extend(compound.entries.iter().map(|entry| line(file, entry)));
    }
    assert_eq!(got, expected);
}

#[test]
fn a_storage_holds_its_children() {
    let data = std::fs::read(fixtures("compound/plaso/Document.doc")).unwrap();
    let file = CompoundFile::parse(&data).unwrap();
    let index = |path: &str| file.entries.iter().position(|e| e.path == path);
    let store = index("Root Entry/MsoDataStore").unwrap();
    let children: Vec<&str> = file
        .entries
        .iter()
        .filter(|e| e.parent == Some(store))
        .map(|e| e.name.as_str())
        .collect();
    assert_eq!(children.len(), 1);
    assert_eq!(file.entries[store].parent, index("Root Entry"));
    assert_eq!(
        file.entries[store].created.and_then(|t| t.to_iso8601()),
        Some("2013-05-16T02:29:49.7040000Z".to_owned())
    );
    let summary = &file.entries[index("Root Entry/\u{5}SummaryInformation").unwrap()];
    assert_eq!(
        file.contents(summary).unwrap(),
        file.stream("\u{5}SummaryInformation").unwrap().unwrap()
    );
}

mod damage {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_000))]

        /// `Document.doc` with bytes changed anywhere (tables, directory
        /// links, streams) or cut: parsed or refused, never a panic; every
        /// parent is an entry, and the root reaches each entry once at most.
        #[test]
        fn damaged_files_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40), cut in any::<usize>()) {
            let mut data = std::fs::read(fixtures("compound/plaso/Document.doc")).unwrap();
            for (at, byte) in flips {
                let len = data.len();
                data[at % len] = byte;
            }
            data.truncate(cut % (data.len() + 1));
            if let Ok(file) = CompoundFile::parse(&data) {
                for entry in &file.entries {
                    prop_assert!(entry.parent.map_or(true, |p| p < file.entries.len()));
                    prop_assert!(entry.path.matches('/').count() < file.entries.len());
                    let _ = file.contents(entry);
                }
            }
        }
    }
}
