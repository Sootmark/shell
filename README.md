# shell

Windows shell data, written from the public documentation (libyal's "Windows Shell Item format" and "Jump lists format", Microsoft's MS-SHLLINK and MS-CFB): shell items, the building blocks of ShellBags, LNK files and jump lists; LNK files; jump lists; and the compound files automatic jump lists are stored in. No dependencies.

```toml
[dependencies]
sootmark-shell = "0.2"
```

```rust
let link = shell::lnk::parse(&std::fs::read("report.docx.lnk")?)?;
println!("{} ({})", link.local_path, link.target_path());
if let Some(tracker) = &link.tracker {
    println!("made on {} ({})", tracker.machine_id, tracker.mac);
}

// What Explorer (AppID f01b4d95cf55d32a) offered in its taskbar menu.
let list = shell::jumplist::automatic(&std::fs::read("f01b4d95cf55d32a.automaticDestinations-ms")?)?;
for d in &list.destinations {
    println!("{} used {} times, pinned: {}", d.path, d.access_count.unwrap_or(0), d.pin.is_some());
}
```

## What you get

- `lnk::parse`: the target's times, size and attributes as they were when the link was saved; its shell items (`target_path()`), volume (type, serial number, label), local path, network share, string data (name, relative path, working directory, arguments, icon), the environment-variable target, the tracker block (machine name, volume and object identifiers, the MAC address and creation time in the object identifier) and the extra data blocks present.
- `jumplist::automatic`: each `DestList` entry (entry number, last use, pin position, access count on Windows 10 and later, machine name, the tracker's volume and file identifiers now and at birth, with the time and MAC address in the file identifier, the recorded path) and its link, most recent first. `jumplist::custom`: the categories an application defined (named, frequent or recent, tasks) and their links.
- `compound`: compound files (OLE, MS-CFB): the directory and any stream, from either sector size, mini streams included. Every chain and count is bounded by the file: a looping or truncated table is an error, not a hang or a huge allocation.
- `item`: shell items (root and known folders, drives, folders and files with their long names, FAT times and NTFS references, control panel pages and categories, "Users Files" delegates, property views (apps under Applications included), network locations, URIs). Other classes are reported as unknown with their class byte, not guessed. Root and known folders are named as Eric Zimmerman's tools name them.

## How it's checked

- Eric Zimmerman's LNK test set (MIT; `tests/fixtures/EZ-LICENSE.txt`, which also covers his jump lists): 552 links from Windows XP to 10, every column LECmd reports compared (times, size, attributes, flags, volume, local and network paths, strings, machine, MAC, tracker time, MFT reference, extra blocks, target path); where LECmd shows a localized resource string, a short name or garbled text in a path, the difference is documented in `tests/lnk.rs`. The damaged file is refused.
- Jump lists against JLECmd: Eric Zimmerman's test set (MIT; Windows 7, 8.0, 8.1 and 10), plaso's (Apache-2.0; `tests/fixtures/jumplist/plaso/LICENSE-plaso.txt`) and a synthetic custom list; 31 `DestList` entries on every column (entry, order, times, machine, MAC, counts, pins, the four identifiers, path) with their links, and 17 custom links. JLECmd names only the first category of a custom list; the others are checked by hand in `tests/jumplist.rs`.
- Corrupted and truncated links and jump lists, and arbitrary bytes (property tests): parsed or refused, never a panic.

## Licence

MIT or Apache-2.0, at your option. The test links and most test jump lists are Eric Zimmerman's, under the MIT licence; plaso's test jump lists are under the Apache licence 2.0.
