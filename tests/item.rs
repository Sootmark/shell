//! Shell items built here, for kinds the test sets hold too few of.

use shell::item::{decode, Kind};

/// A property storage (`1SPS`) of `System.ItemNameDisplay` (FMTID
/// `{B725F130-…}`, id 10) holding `name`.
fn display_name_store(name: &str) -> Vec<u8> {
    let text: Vec<u8> = name
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut value = Vec::new();
    value.extend_from_slice(&0u32.to_le_bytes()); // size, patched below
    value.extend_from_slice(&10u32.to_le_bytes()); // id
    value.push(0); // reserved
    value.extend_from_slice(&0x1fu16.to_le_bytes()); // VT_LPWSTR
    value.extend_from_slice(&0u16.to_le_bytes()); // padding
    value.extend_from_slice(&((text.len() / 2) as u32).to_le_bytes());
    value.extend_from_slice(&text);
    let len = value.len() as u32;
    value[..4].copy_from_slice(&len.to_le_bytes());
    let fmtid = [
        0x30, 0xf1, 0x25, 0xb7, 0xef, 0x47, 0x1a, 0x10, 0xa5, 0xf1, 0x02, 0x60, 0x8c, 0x9e, 0xeb,
        0xac,
    ];
    let mut storage = vec![0; 4];
    storage.extend_from_slice(b"1SPS");
    storage.extend_from_slice(&fmtid);
    storage.extend_from_slice(&value);
    storage.extend_from_slice(&0u32.to_le_bytes()); // no more values
    let len = storage.len() as u32;
    storage[..4].copy_from_slice(&len.to_le_bytes());
    storage
}

#[test]
fn an_app_under_applications_is_named_from_its_properties() {
    // Class 0x00, `APPS` at offset 6, the property store after it.
    let mut item = vec![0, 0, 0x00, 0x00, 0, 0];
    item.extend_from_slice(b"APPS");
    item.extend_from_slice(&display_name_store("Settings"));
    item.extend_from_slice(&[0; 8]);
    let len = item.len() as u16;
    item[..2].copy_from_slice(&len.to_le_bytes());
    let decoded = decode(&item);
    assert_eq!(decoded.kind, Kind::PropertyView);
    assert_eq!(decoded.name, "Settings");
}
