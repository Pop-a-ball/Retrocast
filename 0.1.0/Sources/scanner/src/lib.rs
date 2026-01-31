use chrono::{DateTime, NaiveDateTime, Utc};
use std::fs;
use regex::Regex;
use serde::Serialize;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar, c_void};
use encoding_rs::WINDOWS_1251;

const THRESHOLD_STR: &str = "2026-01-13T23:59:59Z";

#[derive(Serialize)]
struct Decision {
    decision: String,
    reason: String,
    matched: Option<String>,
}

fn normalize_bytes(bytes: &[u8]) -> String {
    // Try UTF-8 first, fallback to CP1251
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    let (cow, _enc_used, _had_errors) = WINDOWS_1251.decode(bytes);
    cow.into_owned()
}

fn find_dates(s: &str) -> Vec<(String, Option<DateTime<Utc>>)> {
    // A few common date patterns, will be expanded
    // ISO like 2025-12-31 or 2025/12/31 optionally with time
    let patterns = vec![
        // ISO: 2025-12-31 or 2025/12/31 optionally with time T12:34:56 or space
        r"(?P<iso>\b(?P<y>\d{4})[-/](?P<m>\d{1,2})[-/](?P<d>\d{1,2})(?:[ T](?P<h>\d{1,2}):(?P<min>\d{2})(?::(?P<s>\d{2}))?)?\b)",
        // DMY: 31.12.2025 or 31/12/2025 optionally with time
        r"(?P<dmy>\b(?P<d1>\d{1,2})[./](?P<m1>\d{1,2})[./](?P<y1>\d{4})(?:[ T](?P<h1>\d{1,2}):(?P<min1>\d{2}))?\b)",
        // RFC-like: 23 Dec 2025
        r"(?P<rfc>\b(?P<dr>\d{1,2})\s+(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{4}\b)",
    ];

    let mut res = vec![];
    for p in patterns.iter() {
        let re = match Regex::new(p) {
            Ok(r) => r,
            Err(e) => { eprintln!("Invalid regex '{}': {}", p, e); continue; }
        };
        for caps in re.captures_iter(s) {
            if let Some(m) = caps.name("iso") {
                let y: i32 = caps.name("y").unwrap().as_str().parse().unwrap();
                let mth: u32 = caps.name("m").unwrap().as_str().parse().unwrap();
                let d: u32 = caps.name("d").unwrap().as_str().parse().unwrap();
                let h: u32 = caps.name("h").map(|m| m.as_str().parse().unwrap()).unwrap_or(0);
                let min: u32 = caps.name("min").map(|m| m.as_str().parse().unwrap()).unwrap_or(0);
                let ssec: u32 = caps.name("s").map(|m| m.as_str().parse().unwrap()).unwrap_or(0);
                // Build NaiveDateTime from components using the safe Option helpers
                if let Some(ndt) = chrono::NaiveDate::from_ymd_opt(y, mth, d)
                    .and_then(|d0| d0.and_hms_opt(h, min, ssec))
                {
                    let dt = DateTime::<Utc>::from_utc(ndt, Utc);
                    res.push((m.as_str().to_string(), Some(dt)));
                } else {
                    res.push((m.as_str().to_string(), None));
                }
            } else if let Some(m2) = caps.name("dmy") {
                let d: u32 = caps.name("d1").unwrap().as_str().parse().unwrap();
                let mth: u32 = caps.name("m1").unwrap().as_str().parse().unwrap();
                let y: i32 = caps.name("y1").unwrap().as_str().parse().unwrap();
                let h: u32 = caps.name("h1").map(|m| m.as_str().parse().unwrap()).unwrap_or(0);
                let min: u32 = caps.name("min1").map(|m| m.as_str().parse().unwrap()).unwrap_or(0);
                if let Some(ndt) = chrono::NaiveDate::from_ymd_opt(y, mth, d)
                    .and_then(|d0| d0.and_hms_opt(h, min, 0))
                {
                    let dt = DateTime::<Utc>::from_utc(ndt, Utc);
                    res.push((m2.as_str().to_string(), Some(dt)));
                } else {
                    res.push((m2.as_str().to_string(), None));
                }
            } else if let Some(m3) = caps.name("rfc") {
                // Minimal RFC parse: "23 Dec 2026" -> convert month
                let text = m3.as_str().to_string();
                // crude parse
                let parts: Vec<&str> = text.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Ok(day) = parts[0].parse::<u32>() {
                        let mon_str = parts[1].trim_matches('.');
                        let mon = match &mon_str[0..3].to_lowercase()[..] {
                            "jan" => 1,
                            "feb" => 2,
                            "mar" => 3,
                            "apr" => 4,
                            "may" => 5,
                            "jun" => 6,
                            "jul" => 7,
                            "aug" => 8,
                            "sep" => 9,
                            "oct" => 10,
                            "nov" => 11,
                            "dec" => 12,
                            _ => 0,
                        };
                        if mon > 0 {
                            if let Ok(year) = parts[2].parse::<i32>() {
                                if let Some(ndt) = chrono::NaiveDate::from_ymd_opt(year, mon, day)
                                    .and_then(|d0| d0.and_hms_opt(0, 0, 0))
                                {
                                    let dt = DateTime::<Utc>::from_utc(ndt, Utc);
                                    res.push((text, Some(dt)));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    res
}

#[no_mangle]
pub extern "C" fn analyze_payload(ptr: *const c_uchar, len: usize) -> i32 {
    // Returns: 0 = allow, 1 = block (future date), 2 = (reserved - previously used for no-date block)
    // NOTE: Temporarily treat empty payload / no-dates as ALLOW (return 0) to disable "no-date" blocking.
    if ptr.is_null() || len == 0 {
        return 0; // allow when empty
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    let normalized = normalize_bytes(slice);
    let matches = find_dates(&normalized);
    if matches.is_empty() {
        // Previously blocked when no dates were found. Now allow by default.
        return 0; // allow - no dates
    }
    // parse threshold + enabled flag from threshold.txt (if present)
    let (threshold, enabled) = load_threshold_from_files()
        .unwrap_or_else(|| (DateTime::parse_from_rfc3339(THRESHOLD_STR).unwrap().with_timezone(&Utc), true));
    if !enabled {
        return 0; // filtering disabled
    }
    for (_text, dt_opt) in matches.iter() {
        if let Some(dt) = dt_opt {
            if *dt > threshold {
                return 1; // block - future date
            }
        } else {
            // unparsed date token: do not block — skip this token
            // (previously returned block; changed to avoid false positives)
            continue;
        }
    }
    0
}

// New helper that returns JSON decision — used by scanner_server (internal) and FFI wrapper
pub fn analyze_payload_json_rust_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        let d = Decision { decision: "allow".to_string(), reason: "empty_payload".to_string(), matched: None };
        return serde_json::to_string(&d).unwrap();
    }
    let normalized = normalize_bytes(bytes);
    let matches = find_dates(&normalized);
    if matches.is_empty() {
        // Previously returned block for no dates; now allow but indicate no_dates_found in reason.
        let d = Decision { decision: "allow".to_string(), reason: "no_dates_found_allowed".to_string(), matched: None };
        return serde_json::to_string(&d).unwrap();
    }
    let (threshold, enabled) = load_threshold_from_files()
        .unwrap_or_else(|| (DateTime::parse_from_rfc3339(THRESHOLD_STR).unwrap().with_timezone(&Utc), true));
    if !enabled {
        let d = Decision { decision: "allow".to_string(), reason: "filter_disabled".to_string(), matched: None };
        return serde_json::to_string(&d).unwrap();
    }
    for (text, dt_opt) in matches.iter() {
        if let Some(dt) = dt_opt {
            if *dt > threshold {
                let d = Decision { decision: "block".to_string(), reason: "date_after_threshold".to_string(), matched: Some(text.clone()) };
                return serde_json::to_string(&d).unwrap();
            }
        } else {
            // unparseable token — skip and do not block
            continue;
        }
    }
    let d = Decision { decision: "allow".to_string(), reason: "all_dates_ok".to_string(), matched: Some(matches[0].0.clone()) };
    serde_json::to_string(&d).unwrap()
}

#[no_mangle]
pub extern "C" fn analyze_payload_json(ptr: *const c_uchar, len: usize) -> *mut c_char {
    if ptr.is_null() || len == 0 {
        let s = analyze_payload_json_rust_bytes(&[]);
        return CString::new(s).unwrap().into_raw();
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    let s = analyze_payload_json_rust_bytes(slice);
    CString::new(s).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_cstring(ptr: *mut c_char) {
    if ptr.is_null() { return }
    unsafe { CString::from_raw(ptr) }; // dropped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_iso() {
        let s = "This contains a date 2025-12-22T12:00:00 and another 2026-01-01";
        let m = find_dates(s);
        assert!(m.len() >= 1);
    }

    #[test]
    fn test_analyze_future() {
        let s = b"Date: 2026/01/01";
        let r = analyze_payload(s.as_ptr(), s.len());
        assert_eq!(r, 1);
    }

    #[test]
    fn test_analyze_no_date() {
        let s = b"Hello world";
        let r = analyze_payload(s.as_ptr(), s.len());
        assert_eq!(r, 0);  // No dates found => ALLOW (0)
    }

    #[test]
    fn test_analyze_allow() {
        let s = b"event on 2025-01-01";
        let r = analyze_payload(s.as_ptr(), s.len());
        assert_eq!(r, 0);
    }

    #[test]
    fn test_server_helper_future() {
        let s = b"Date: 2026/01/01";
        let json = analyze_payload_json_rust_bytes(s);
        assert!(json.contains("block"));
        assert!(json.contains("date_after_threshold"));
    }

    #[test]
    fn test_server_helper_no_date() {
        let s = b"Hello";
        let json = analyze_payload_json_rust_bytes(s);
        assert!(json.contains("allow") && json.contains("no_dates_found_allowed"));
    }
}

fn load_threshold_from_files() -> Option<(DateTime<Utc>, bool)> {
    // Candidate paths (relative to current working directory)
    let candidates = [
        "threshold.txt",
        "prototype/scanner/threshold.txt",
        "../scanner/threshold.txt",
        "./scanner/threshold.txt",
    ];
    for p in candidates.iter() {
        if let Ok(s) = fs::read_to_string(p) {
            let mut enabled: Option<bool> = None;
            let mut dt_opt: Option<DateTime<Utc>> = None;
            for raw_line in s.lines() {
                let line = raw_line.trim();
                if line.is_empty() { continue; }
                // Check for simple enabled flag
                if line == "0" {
                    enabled = Some(false);
                    continue;
                }
                if line == "1" {
                    enabled = Some(true);
                    continue;
                }
                if line.to_lowercase().starts_with("enabled=") {
                    let parts: Vec<&str> = line.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        let v = parts[1].trim();
                        if v == "0" { enabled = Some(false); }
                        else if v == "1" { enabled = Some(true); }
                    }
                    continue;
                }
                // Try RFC3339 first
                if let Ok(dt) = DateTime::parse_from_rfc3339(line) {
                    dt_opt = Some(dt.with_timezone(&Utc));
                    continue;
                }
                // Try plain date YYYY-MM-DD (append end-of-day)
                if let Ok(ndt) = NaiveDateTime::parse_from_str(&format!("{}T23:59:59", line), "%Y-%m-%dT%H:%M:%S") {
                    dt_opt = Some(DateTime::<Utc>::from_utc(ndt, Utc));
                    continue;
                }
                // Try parsing as NaiveDate only
                if let Ok(d) = chrono::NaiveDate::parse_from_str(line, "%Y-%m-%d") {
                    if let Some(ndt) = d.and_hms_opt(23,59,59) {
                        dt_opt = Some(DateTime::<Utc>::from_utc(ndt, Utc));
                        continue;
                    }
                }
            }
            if let Some(dt) = dt_opt {
                // default enabled true unless explicitly set to false in the file
                let en = enabled.unwrap_or(true);
                return Some((dt, en));
            }
            // If file provided only enabled flag but no date, ignore and continue
        }
    }
    None
}