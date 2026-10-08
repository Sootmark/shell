//! Windows shell data: shell items ([`item`]), the building blocks of
//! ShellBags, LNK files and jump lists; LNK files ([`lnk`]); jump lists
//! ([`jumplist`]) and the compound files they're stored in ([`compound`]).
//!
//! Written from the public documentation: libyal's "Windows Shell Item
//! format" and "Jump lists format", Microsoft's MS-SHLLINK and MS-CFB. One
//! dependency, its sibling `sootmark-common` (times); every read is
//! bounds-checked and damage is reported, never a panic.

pub mod compound;
pub mod item;
pub mod jumplist;
pub mod lnk;

/// This crate's version, for provenance.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}
