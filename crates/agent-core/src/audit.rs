//! Who connected, when, and whether they were let in.
//!
//! **What this deliberately never records: anything that was typed, copied, or shown.** An agent
//! that can see a root console and synthesise keystrokes is one bad logging decision away from
//! being a keylogger with a log file (THREAT-MODEL §10). Peer address, certificate fingerprint and
//! outcome are enough to answer "did something else pair with this machine", which is the question
//! an audit log exists for.
//!
//! Lines also go to stderr, so under systemd they land in the journal with its own timestamps; the
//! file matters on Windows, where the agent is a logon task whose stderr goes nowhere.

use std::io::Write;
use std::path::Path;

/// Past this size the log is rotated once, so a machine that is scanned continuously cannot fill
/// the disk out of a directory nobody watches. Two files, ~2 MiB in total, forever.
const MAX_BYTES: u64 = 1 << 20;

pub fn record(dir: &Path, event: &str) {
    let line = format!("{} {}\n", stamp(std::time::SystemTime::now()), event);
    eprint!("[hublot] audit {line}");

    let path = dir.join("audit.log");
    if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) >= MAX_BYTES {
        let _ = std::fs::rename(&path, dir.join("audit.log.1"));
    }
    // A log that cannot be written must not take the agent down with it: the console mirror is the
    // job, and refusing to serve because a disk is full would be the wrong trade.
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// `YYYY-MM-DD HH:MM:SSZ`, computed rather than depended on.
///
/// A date crate would be three more dependencies in the process with the most attack surface in
/// the project (THREAT-MODEL §5), to turn one integer into eight fields. The civil-from-days
/// algorithm is Howard Hinnant's, and the test below pins it against known instants.
fn stamp(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn at(secs: u64) -> String {
        stamp(UNIX_EPOCH + Duration::from_secs(secs))
    }

    #[test]
    fn known_instants() {
        assert_eq!(at(0), "1970-01-01 00:00:00Z");
        assert_eq!(at(1_000_000_000), "2001-09-09 01:46:40Z");
        // A leap day, which is where hand-rolled date maths goes wrong.
        assert_eq!(at(1_709_164_800), "2024-02-29 00:00:00Z");
        // The day after, to catch an off-by-one that only shows on the far side of one.
        assert_eq!(at(1_709_251_200), "2024-03-01 00:00:00Z");
        assert_eq!(at(1_753_401_600), "2025-07-25 00:00:00Z");
    }
}
