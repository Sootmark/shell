//! What the oracle tests share: the fixtures, a CSV reader, and EZ Tools'
//! display forms.

use std::collections::HashMap;
use std::path::Path;

pub fn fixtures() -> &'static Path {
    Box::leak(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .into_boxed_path(),
    )
}

pub fn records(text: &str) -> Vec<HashMap<String, String>> {
    let (mut rows, mut row, mut field, mut quoted) = (Vec::new(), Vec::new(), String::new(), false);
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => row.push(std::mem::take(&mut field)),
            '\r' if !quoted => {}
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            c => field.push(c),
        }
    }
    let header = rows.remove(0);
    rows.into_iter()
        .map(|r| header.iter().cloned().zip(r).collect())
        .collect()
}

/// FILETIME as LECmd prints it: `2015-12-16 16:39:14`; empty for 0.
pub fn when(filetime: u64) -> String {
    if filetime == 0 {
        return String::new();
    }
    let secs = (filetime / 10_000_000) as i64 - 11_644_473_600;
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

/// Whether an EZ Tools path matches ours, component by component, where
/// theirs isn't a display form: a localized resource string (`@shell32.dll,
/// -21781` for "Program Files"), a short 8.3 name where the item holds the
/// long one, or garbled text after an identifier it doesn't know (an ANSI
/// string read as UTF-16).
pub fn path_agrees(theirs: &str, ours: &str) -> bool {
    let (a, b): (Vec<&str>, Vec<&str>) = (theirs.split('\\').collect(), ours.split('\\').collect());
    a.len() == b.len()
        && a.iter().zip(&b).all(|(x, y)| {
            x == y || x.starts_with('@') || x.contains('~') || *x == "(None)" || !x.is_ascii()
        })
}
