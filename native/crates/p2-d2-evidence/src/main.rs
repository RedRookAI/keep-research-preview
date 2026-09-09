#![forbid(unsafe_code)]

use keep_native_p2_d2_evidence::audit_plan::capture_audit_plan_v1;
use keep_native_p2_d2_evidence::{capture_patch_byte_carrier_set, capture_patch_overlay};
use keep_native_protocol::patch_capture::{ArchiveFormat, MAX_INPUT_BYTES, capture_archive};
use std::io::{self, BufRead};

fn decode_hex(text: &str) -> Result<Vec<u8>, &'static str> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex");
    }
    if text.len() / 2 > MAX_INPUT_BYTES {
        return Err("LIMIT");
    }
    fn digit(byte: u8) -> Result<u8, &'static str> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err("invalid hex"),
        }
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(text.len() / 2)
        .map_err(|_| "LIMIT")?;
    for pair in text.as_bytes().chunks_exact(2) {
        bytes.push((digit(pair[0])? << 4) | digit(pair[1])?);
    }
    Ok(bytes)
}

// Fixture oracle, not the installed capture service. Bound the diagnostic line
// before allocation; an oversized line terminates instead of draining forever.
fn bounded_line(reader: &mut impl BufRead) -> Result<Option<String>, &'static str> {
    const MAX_LINE: usize = 2 * MAX_INPUT_BYTES + 4096;
    let mut line = Vec::new();
    loop {
        let pending = reader.fill_buf().map_err(|_| "stdin")?;
        if pending.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                String::from_utf8(line)
                    .map(Some)
                    .map_err(|_| "invalid utf8")
            };
        }
        let end = pending.iter().position(|byte| *byte == b'\n');
        let take = end.unwrap_or(pending.len());
        let length = line
            .len()
            .checked_add(take)
            .filter(|n| *n <= MAX_LINE)
            .ok_or("LIMIT")?;
        if length > line.capacity() {
            let capacity = length.max(line.capacity().saturating_mul(2)).min(MAX_LINE);
            line.try_reserve_exact(capacity - line.len())
                .map_err(|_| "LIMIT")?;
        }
        line.extend_from_slice(&pending[..take]);
        reader.consume(take + usize::from(end.is_some()));
        if end.is_some() {
            return String::from_utf8(line)
                .map(Some)
                .map_err(|_| "invalid utf8");
        }
    }
}

fn main() {
    let mut stdin = io::stdin().lock();
    loop {
        let line = match bounded_line(&mut stdin) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                println!("ERR\t{error}");
                break;
            }
        };
        let result = (|| {
            if let Some(source) = line.strip_prefix("SOURCE\t") {
                let fields: Vec<_> = source.splitn(4, '\t').collect();
                if fields.len() != 3 {
                    return Err("MALFORMED");
                }
                let format = match fields[0] {
                    "TAR" => ArchiveFormat::Tar,
                    "TAR_GZIP" => ArchiveFormat::TarGzip,
                    _ => return Err("MALFORMED"),
                };
                let bytes = decode_hex(fields[2])?;
                let rows = capture_archive(&bytes, format, fields[1]).map_err(|e| e.code())?;
                Ok(format!(
                    "SOURCE\t{}\t{}\t{}",
                    rows.row_digest(),
                    rows.files().len(),
                    rows.byte_length()
                ))
            } else if let Some(hex) = line.strip_prefix("AUDIT\t") {
                decode_hex(hex.trim()).and_then(|bytes| {
                    capture_audit_plan_v1(&bytes)
                        .map(|capture| capture.audit_plan_digest().to_owned())
                        .map_err(|error| error.0)
                })
            } else if let Some(hex) = line.strip_prefix("CARRIER\t") {
                decode_hex(hex.trim()).and_then(|bytes| {
                    capture_patch_byte_carrier_set(&bytes)
                        .map(|capture| capture.patch_byte_carrier_set_digest().to_owned())
                        .map_err(|error| error.0)
                })
            } else {
                decode_hex(line.trim()).and_then(|bytes| {
                    capture_patch_overlay(&bytes)
                        .map(|capture| capture.patch_overlay_digest().to_owned())
                        .map_err(|error| error.0)
                })
            }
        })();
        match result {
            Ok(digest) => println!("OK\t{digest}"),
            Err(error) => println!("ERR\t{error}"),
        }
    }
}
