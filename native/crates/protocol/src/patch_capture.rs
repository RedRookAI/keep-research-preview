#![forbid(unsafe_code)]

//! Pure owned patch-source data. No filesystem, signing, build or launch authority.
use crate::p2_schema::canonical_relative;
use crate::{Limits, Sha256State, Value, encode_bounded};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

pub const MAX_INPUT_BYTES: usize = 144 * 1024 * 1024;
pub const MAX_EXPANDED_BYTES: usize = 144 * 1024 * 1024;
pub const MAX_SOURCE_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SOURCE_FILES: usize = 4096;
pub const MAX_DIRECTORIES: usize = 8192;
pub const MAX_CAPTURE_FRAME_BYTES: usize = 65_536;
pub const CAPTURE_CHUNK_BYTES: usize = 32 * 1024;
pub const MAX_CAPTURE_FRAMES: usize = 32_768;
pub const MAX_CAPTURE_RESPONSE_BYTES: usize = 320 * 1024 * 1024;
pub const CAPTURE_FRAME_LIMITS: Limits = Limits {
    max_bytes: MAX_CAPTURE_FRAME_BYTES,
    max_depth: 16,
    max_items: 1024,
    max_collection_items: 32,
    max_text_bytes: 4096,
};
pub const CAPTURE_REQUEST_DOMAIN: &[u8] = b"keep.patch-input-request/v1\0";
pub const CAPTURE_RESPONSE_DOMAIN: &[u8] = b"keep.patch-input-response/v1\0";
pub const CAPTURE_ROWS_LIMITS: Limits = Limits {
    max_bytes: 20 * 1024 * 1024,
    max_depth: 16,
    max_items: 65_536,
    max_collection_items: MAX_SOURCE_FILES,
    max_text_bytes: 4096,
};
const ROW_DOMAIN: &[u8] = b"keep.patch-source-rows/v1\0";
const ROW_SCHEMA: &str = "keep.patch-source-rows";
const PACKAGE: &str = "curve25519-dalek@5.0.0";
const PREFIX: &str = "curve25519-dalek-5.0.0/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureError {
    Malformed,
    Limit,
    Path,
    Type,
    Integrity,
    Race,
    Unsupported,
    Io,
    Cancelled,
}
impl CaptureError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Malformed => "MALFORMED",
            Self::Limit => "LIMIT",
            Self::Path => "PATH",
            Self::Type => "TYPE",
            Self::Integrity => "INTEGRITY",
            Self::Race => "RACE",
            Self::Unsupported => "UNSUPPORTED",
            Self::Io => "IO",
            Self::Cancelled => "CANCELLED",
        }
    }
}
impl Display for CaptureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for CaptureError {}

pub fn byte_digest(bytes: &[u8]) -> String {
    let mut hash = Sha256State::new();
    hash.update(bytes);
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn valid_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && text.bytes().any(|byte| byte != b'0')
}

#[derive(Debug)]
pub enum CaptureSource {
    Directory {
        expected_row_digest: String,
        declared_base_archive_digest: String,
    },
    Archive {
        format: ArchiveFormat,
        stream_digest: String,
    },
}

/// Closed, canonical request data. Private fields prevent callers from bypassing
/// parsing or mutating paths/hashes after admission. This is never effect authority.
#[derive(Debug)]
pub struct ValidatedCaptureRequest {
    root: String,
    source_path: String,
    overlay_path: String,
    overlay_byte_digest: String,
    carrier_path: String,
    carrier_byte_digest: String,
    source: CaptureSource,
    digest: String,
}
impl ValidatedCaptureRequest {
    pub fn root(&self) -> &str {
        &self.root
    }
    pub fn source_path(&self) -> &str {
        &self.source_path
    }
    pub fn overlay_path(&self) -> &str {
        &self.overlay_path
    }
    pub fn overlay_byte_digest(&self) -> &str {
        &self.overlay_byte_digest
    }
    pub fn carrier_path(&self) -> &str {
        &self.carrier_path
    }
    pub fn carrier_byte_digest(&self) -> &str {
        &self.carrier_byte_digest
    }
    pub fn source(&self) -> &CaptureSource {
        &self.source
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn source_kind(&self) -> &'static str {
        match self.source {
            CaptureSource::Directory { .. } => "directory",
            CaptureSource::Archive {
                format: ArchiveFormat::Tar,
                ..
            } => "tar",
            CaptureSource::Archive {
                format: ArchiveFormat::TarGzip,
                ..
            } => "tar-gzip",
        }
    }
    pub fn overlay_base_digest(&self) -> &str {
        match &self.source {
            CaptureSource::Directory {
                declared_base_archive_digest,
                ..
            } => declared_base_archive_digest,
            CaptureSource::Archive { stream_digest, .. } => stream_digest,
        }
    }
}

pub fn capture_input_request(bytes: &[u8]) -> Result<ValidatedCaptureRequest, CaptureError> {
    if bytes.len() > MAX_CAPTURE_FRAME_BYTES {
        return Err(CaptureError::Limit);
    }
    let value = crate::decode_canonical(bytes, CAPTURE_FRAME_LIMITS)
        .map_err(|_| CaptureError::Malformed)?;
    let Value::Map(fields) = &value else {
        return Err(CaptureError::Malformed);
    };
    let text = |key: &str| {
        value
            .field(key)
            .and_then(Value::as_text)
            .ok_or(CaptureError::Malformed)
    };
    if text("schema")? != "keep.patch-input-capture"
        || value.field("version").and_then(Value::as_u64) != Some(1)
    {
        return Err(CaptureError::Malformed);
    }
    let kind = text("sourceKind")?;
    let specific: &[&str] = match kind {
        "directory" => &["expectedSourceRowDigest", "declaredBaseArchiveDigest"],
        "tar" | "tar-gzip" => &["sourceStreamDigest"],
        _ => return Err(CaptureError::Malformed),
    };
    const COMMON: &[&str] = &[
        "schema",
        "version",
        "root",
        "sourcePath",
        "sourceKind",
        "overlayPath",
        "overlayByteDigest",
        "carrierPath",
        "carrierByteDigest",
    ];
    if fields.len() != COMMON.len() + specific.len()
        || fields
            .iter()
            .any(|(key, _)| !COMMON.contains(&key.as_str()) && !specific.contains(&key.as_str()))
    {
        return Err(CaptureError::Malformed);
    }
    let root = text("root")?;
    if root.len() > 4096 || !root.strip_prefix('/').is_some_and(canonical_relative) {
        return Err(CaptureError::Path);
    }
    let paths = [
        text("sourcePath")?,
        text("overlayPath")?,
        text("carrierPath")?,
    ];
    for path in paths {
        if path.len() > 4096 || !canonical_relative(path) {
            return Err(CaptureError::Path);
        }
    }
    // Input locations must be disjoint, including case-folded aliases and either
    // nesting direction. A source directory cannot absorb its own control inputs.
    for left in 0..paths.len() {
        for right in left + 1..paths.len() {
            let a = paths[left].to_ascii_lowercase();
            let b = paths[right].to_ascii_lowercase();
            if a == b || a.starts_with(&format!("{b}/")) || b.starts_with(&format!("{a}/")) {
                return Err(CaptureError::Path);
            }
        }
    }
    let digest = |key: &str| -> Result<String, CaptureError> {
        let result = text(key)?;
        if !valid_digest(result) {
            return Err(CaptureError::Malformed);
        }
        Ok(result.to_owned())
    };
    let source = if kind == "directory" {
        CaptureSource::Directory {
            expected_row_digest: digest("expectedSourceRowDigest")?,
            declared_base_archive_digest: digest("declaredBaseArchiveDigest")?,
        }
    } else {
        CaptureSource::Archive {
            format: if kind == "tar" {
                ArchiveFormat::Tar
            } else {
                ArchiveFormat::TarGzip
            },
            stream_digest: digest("sourceStreamDigest")?,
        }
    };
    let mut hash = Sha256State::new();
    hash.update(CAPTURE_REQUEST_DOMAIN);
    hash.update(bytes);
    Ok(ValidatedCaptureRequest {
        root: root.into(),
        source_path: paths[0].into(),
        overlay_path: paths[1].into(),
        carrier_path: paths[2].into(),
        overlay_byte_digest: digest("overlayByteDigest")?,
        carrier_byte_digest: digest("carrierByteDigest")?,
        source,
        digest: hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}
pub fn validate_source_path(path: &str) -> Result<(), CaptureError> {
    if path.len() > 4096 || !canonical_relative(path) || path == ".cargo-checksum.json" {
        return Err(CaptureError::Path);
    }
    if path.split('/').count() > 32 || path.split('/').any(|part| part.len() > 255) {
        return Err(CaptureError::Limit);
    }
    Ok(())
}
pub fn validate_source_mode(mode: u32) -> Result<(), CaptureError> {
    if mode > 0o777 {
        Err(CaptureError::Type)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub struct CapturedSourceFile {
    path: String,
    mode: u32,
    bytes: Vec<u8>,
    byte_digest: String,
}
impl CapturedSourceFile {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn mode(&self) -> u32 {
        self.mode
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn byte_digest(&self) -> &str {
        &self.byte_digest
    }
    fn metadata(&self) -> Value {
        Value::Map(vec![
            ("path".into(), Value::Text(self.path.clone())),
            ("mode".into(), Value::Unsigned(u64::from(self.mode))),
            (
                "byteLength".into(),
                Value::Unsigned(self.bytes.len() as u64),
            ),
            ("byteDigest".into(), Value::Text(self.byte_digest.clone())),
        ])
    }
}

#[derive(Debug)]
pub struct CapturedSourceRows {
    files: Vec<CapturedSourceFile>,
    byte_length: usize,
    row_digest: String,
}
impl CapturedSourceRows {
    pub fn files(&self) -> &[CapturedSourceFile] {
        &self.files
    }
    pub fn byte_length(&self) -> usize {
        self.byte_length
    }
    pub fn row_digest(&self) -> &str {
        &self.row_digest
    }
}

/// Owns data, not authority. Each successful insertion transfers its byte buffer;
/// failed insertions never change the already captured inventory.
#[derive(Default)]
pub struct SourceRowsBuilder {
    files: Vec<CapturedSourceFile>,
    namespace: BTreeMap<String, (String, bool)>,
    directories: usize,
    total: usize,
}
impl SourceRowsBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn remaining_file_bytes(&self) -> usize {
        MAX_FILE_BYTES.min(MAX_SOURCE_BYTES - self.total)
    }
    /// Admit metadata before a native caller allocates or reads a file body.
    /// The same predicate runs again when owned bytes are actually inserted.
    pub fn check_file(&self, path: &str, mode: u32, size: usize) -> Result<(), CaptureError> {
        self.plan(path, mode, size).map(|_| ())
    }
    fn plan(
        &self,
        path: &str,
        mode: u32,
        size: usize,
    ) -> Result<Vec<(String, String, bool)>, CaptureError> {
        validate_source_path(path)?;
        validate_source_mode(mode)?;
        if self.files.len() >= MAX_SOURCE_FILES || size > self.remaining_file_bytes() {
            return Err(CaptureError::Limit);
        }
        let mut additions = Vec::new();
        let mut prefix = String::new();
        let mut parts = path.split('/').peekable();
        let mut new_directories = 0;
        while let Some(part) = parts.next() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            let file = parts.peek().is_none();
            let folded = prefix.to_ascii_lowercase();
            if let Some((prior, prior_file)) = self.namespace.get(&folded) {
                if prior != &prefix || *prior_file || file {
                    return Err(CaptureError::Path);
                }
            } else {
                if !file {
                    new_directories += 1;
                }
                if self.directories + new_directories > MAX_DIRECTORIES {
                    return Err(CaptureError::Limit);
                }
                additions.push((folded, prefix.clone(), file));
            }
        }
        Ok(additions)
    }
    pub fn push(&mut self, path: String, mode: u32, bytes: Vec<u8>) -> Result<(), CaptureError> {
        let additions = self.plan(&path, mode, bytes.len())?;
        self.files.try_reserve(1).map_err(|_| CaptureError::Limit)?;
        let digest = byte_digest(&bytes);
        for (folded, original, file) in additions {
            self.namespace.insert(folded, (original, file));
            if !file {
                self.directories += 1;
            }
        }
        self.total += bytes.len();
        self.files.push(CapturedSourceFile {
            path,
            mode,
            bytes,
            byte_digest: digest,
        });
        Ok(())
    }
    pub fn finish(mut self) -> Result<CapturedSourceRows, CaptureError> {
        self.files
            .sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        // Canonical map order is files, schema, version, packageId. Stream metadata
        // rather than allocate another giant map/preimage; goldens compare the exact
        // byte stream with the retained canonical encoder.
        let mut hash = Sha256State::new();
        hash.update(ROW_DOMAIN);
        let mut prefix = Vec::new();
        crate::head(5, 4, &mut prefix);
        prefix.extend_from_slice(
            &encode_bounded(&Value::Text("files".into()), CAPTURE_ROWS_LIMITS)
                .map_err(|_| CaptureError::Malformed)?,
        );
        crate::head(4, self.files.len() as u64, &mut prefix);
        let mut length = prefix.len();
        hash.update(&prefix);
        for file in &self.files {
            let bytes = encode_bounded(&file.metadata(), CAPTURE_ROWS_LIMITS)
                .map_err(|_| CaptureError::Limit)?;
            length = length.checked_add(bytes.len()).ok_or(CaptureError::Limit)?;
            if length > CAPTURE_ROWS_LIMITS.max_bytes {
                return Err(CaptureError::Limit);
            }
            hash.update(&bytes);
        }
        for (key, value) in [
            ("schema", Value::Text(ROW_SCHEMA.into())),
            ("version", Value::Unsigned(1)),
            ("packageId", Value::Text(PACKAGE.into())),
        ] {
            for entry in [Value::Text(key.into()), value] {
                let bytes = encode_bounded(&entry, CAPTURE_ROWS_LIMITS)
                    .map_err(|_| CaptureError::Malformed)?;
                length = length.checked_add(bytes.len()).ok_or(CaptureError::Limit)?;
                if length > CAPTURE_ROWS_LIMITS.max_bytes {
                    return Err(CaptureError::Limit);
                }
                hash.update(&bytes);
            }
        }
        let row_digest = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(CapturedSourceRows {
            files: self.files,
            byte_length: self.total,
            row_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveFormat {
    Tar,
    TarGzip,
}

struct PendingFile {
    path: String,
    mode: u32,
    size: usize,
    bytes: Vec<u8>,
}
struct TarParser {
    rows: SourceRowsBuilder,
    header: [u8; 512],
    header_bytes: usize,
    file: Option<PendingFile>,
    padding: usize,
    zero_blocks: usize,
    expanded: usize,
}
impl TarParser {
    fn new() -> Self {
        Self {
            rows: SourceRowsBuilder::new(),
            header: [0; 512],
            header_bytes: 0,
            file: None,
            padding: 0,
            zero_blocks: 0,
            expanded: 0,
        }
    }
    fn write(&mut self, mut input: &[u8]) -> Result<(), CaptureError> {
        self.expanded = self
            .expanded
            .checked_add(input.len())
            .filter(|size| *size <= MAX_EXPANDED_BYTES)
            .ok_or(CaptureError::Limit)?;
        while !input.is_empty() {
            if self.zero_blocks == 2 {
                if input.iter().any(|byte| *byte != 0) {
                    return Err(CaptureError::Malformed);
                }
                return Ok(());
            }
            if let Some(file) = &mut self.file {
                let take = (file.size - file.bytes.len()).min(input.len());
                file.bytes.extend_from_slice(&input[..take]);
                input = &input[take..];
                if file.bytes.len() == file.size {
                    let file = self.file.take().ok_or(CaptureError::Malformed)?;
                    self.padding = (512 - file.size % 512) % 512;
                    self.rows.push(file.path, file.mode, file.bytes)?;
                }
            } else if self.padding != 0 {
                let take = self.padding.min(input.len());
                if input[..take].iter().any(|byte| *byte != 0) {
                    return Err(CaptureError::Malformed);
                }
                self.padding -= take;
                input = &input[take..];
            } else {
                let take = (512 - self.header_bytes).min(input.len());
                self.header[self.header_bytes..self.header_bytes + take]
                    .copy_from_slice(&input[..take]);
                self.header_bytes += take;
                input = &input[take..];
                if self.header_bytes == 512 {
                    self.header_bytes = 0;
                    if self.header.iter().all(|byte| *byte == 0) {
                        self.zero_blocks += 1;
                    } else {
                        if self.zero_blocks != 0 {
                            return Err(CaptureError::Malformed);
                        }
                        let (path, mode, size) = tar_header(&self.header)?;
                        self.rows.plan(&path, mode, size)?;
                        if size == 0 {
                            self.rows.push(path, mode, Vec::new())?;
                        } else {
                            let mut bytes = Vec::new();
                            bytes
                                .try_reserve_exact(size)
                                .map_err(|_| CaptureError::Limit)?;
                            self.file = Some(PendingFile {
                                path,
                                mode,
                                size,
                                bytes,
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn finish(self) -> Result<CapturedSourceRows, CaptureError> {
        if self.zero_blocks != 2
            || self.file.is_some()
            || self.header_bytes != 0
            || self.padding != 0
            || !self.expanded.is_multiple_of(512)
        {
            return Err(CaptureError::Malformed);
        }
        self.rows.finish()
    }
}

fn tar_text(bytes: &[u8]) -> Result<&str, CaptureError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0)
        || bytes[..end]
            .iter()
            .any(|byte| !(0x20..=0x7e).contains(byte))
    {
        return Err(CaptureError::Malformed);
    }
    std::str::from_utf8(&bytes[..end]).map_err(|_| CaptureError::Malformed)
}
fn octal(bytes: &[u8]) -> Result<u64, CaptureError> {
    let start = bytes
        .iter()
        .position(|byte| *byte != b' ')
        .unwrap_or(bytes.len());
    let mut end = start;
    let mut value = 0u64;
    while end < bytes.len() && (b'0'..=b'7').contains(&bytes[end]) {
        value = value
            .checked_mul(8)
            .and_then(|n| n.checked_add(u64::from(bytes[end] - b'0')))
            .ok_or(CaptureError::Limit)?;
        end += 1;
    }
    if bytes[end..].iter().any(|byte| *byte != 0 && *byte != b' ') {
        return Err(CaptureError::Malformed);
    }
    Ok(value)
}
fn tar_header(header: &[u8; 512]) -> Result<(String, u32, usize), CaptureError> {
    let checksum: u64 = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                32
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    if octal(&header[148..156])? != checksum {
        return Err(CaptureError::Integrity);
    }
    if !matches!(header[156], 0 | b'0') {
        return Err(CaptureError::Type);
    }
    let gnu = &header[257..265] == b"ustar  \0";
    let posix = &header[257..265] == b"ustar\000";
    if !gnu && !posix {
        return Err(CaptureError::Malformed);
    }
    if (gnu && header[345..].iter().any(|byte| *byte != 0))
        || header[500..].iter().any(|byte| *byte != 0)
    {
        return Err(CaptureError::Type);
    }
    if !tar_text(&header[157..257])?.is_empty()
        || octal(&header[329..337])? != 0
        || octal(&header[337..345])? != 0
    {
        return Err(CaptureError::Type);
    }
    tar_text(&header[265..297])?;
    tar_text(&header[297..329])?;
    octal(&header[108..116])?;
    octal(&header[116..124])?;
    octal(&header[136..148])?;
    let mode = u32::try_from(octal(&header[100..108])?).map_err(|_| CaptureError::Type)?;
    validate_source_mode(mode)?;
    let size = usize::try_from(octal(&header[124..136])?).map_err(|_| CaptureError::Limit)?;
    if size > MAX_FILE_BYTES {
        return Err(CaptureError::Limit);
    }
    let name = tar_text(&header[..100]).map_err(|_| CaptureError::Path)?;
    let prefix = if posix {
        tar_text(&header[345..500]).map_err(|_| CaptureError::Path)?
    } else {
        ""
    };
    let combined = if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    };
    let path = combined.strip_prefix(PREFIX).ok_or(CaptureError::Path)?;
    validate_source_path(path)?;
    Ok((path.to_owned(), mode, size))
}

/// Captures only inert rows. The caller must separately establish filesystem and
/// provenance custody; a matching expected hash is not signature/launch authority.
pub fn capture_archive(
    bytes: &[u8],
    format: ArchiveFormat,
    expected_stream_digest: &str,
) -> Result<CapturedSourceRows, CaptureError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(CaptureError::Limit);
    }
    if !valid_digest(expected_stream_digest) {
        return Err(CaptureError::Malformed);
    }
    if byte_digest(bytes) != expected_stream_digest {
        return Err(CaptureError::Integrity);
    }
    let mut parser = TarParser::new();
    match format {
        ArchiveFormat::Tar => {
            if bytes.starts_with(&[0x1f, 0x8b]) {
                return Err(CaptureError::Malformed);
            }
            parser.write(bytes)?;
        }
        ArchiveFormat::TarGzip => {
            crate::gzip::decode(bytes, MAX_EXPANDED_BYTES, |part| parser.write(part))?;
        }
    }
    parser.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request_value(kind: &str) -> Value {
        let mut fields = vec![
            (
                "schema".into(),
                Value::Text("keep.patch-input-capture".into()),
            ),
            ("version".into(), Value::Unsigned(1)),
            ("root".into(), Value::Text("/tmp/keep-source".into())),
            ("sourceKind".into(), Value::Text(kind.into())),
            ("sourcePath".into(), Value::Text("source".into())),
            ("overlayPath".into(), Value::Text("overlay.cbor".into())),
            ("overlayByteDigest".into(), Value::Text("3".repeat(64))),
            ("carrierPath".into(), Value::Text("carrier.cbor".into())),
            ("carrierByteDigest".into(), Value::Text("4".repeat(64))),
        ];
        if kind == "directory" {
            fields.push((
                "expectedSourceRowDigest".into(),
                Value::Text("2".repeat(64)),
            ));
            fields.push((
                "declaredBaseArchiveDigest".into(),
                Value::Text("1".repeat(64)),
            ));
        } else {
            fields.push(("sourceStreamDigest".into(), Value::Text("1".repeat(64))));
        }
        Value::Map(fields)
    }
    fn request(value: &Value) -> Result<ValidatedCaptureRequest, CaptureError> {
        capture_input_request(&encode_bounded(value, CAPTURE_FRAME_LIMITS).unwrap())
    }
    #[test]
    fn capture_requests_bind_closed_kind_specific_fields_and_exact_bytes() {
        for kind in ["directory", "tar", "tar-gzip"] {
            let value = request_value(kind);
            let captured = request(&value).unwrap();
            assert_eq!(captured.source_kind(), kind);
            assert_eq!(captured.overlay_base_digest(), "1".repeat(64));
            assert_eq!(captured.root(), "/tmp/keep-source");
            let bytes = encode_bounded(&value, CAPTURE_FRAME_LIMITS).unwrap();
            let mut preimage = CAPTURE_REQUEST_DOMAIN.to_vec();
            preimage.extend_from_slice(&bytes);
            assert_eq!(captured.digest(), byte_digest(&preimage));
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert_eq!(
                capture_input_request(&trailing).unwrap_err(),
                CaptureError::Malformed
            );
            let Value::Map(fields) = value else {
                unreachable!()
            };
            for index in 0..fields.len() {
                let mut missing = fields.clone();
                missing.remove(index);
                assert_eq!(
                    request(&Value::Map(missing)).unwrap_err(),
                    CaptureError::Malformed
                );
                let mut wrong_type = fields.clone();
                wrong_type[index].1 = Value::Null;
                assert_eq!(
                    request(&Value::Map(wrong_type)).unwrap_err(),
                    CaptureError::Malformed
                );
            }
            for key in [
                "sourceDigest",
                "baseArchiveDigest",
                "overlayDigest",
                "carrierDigest",
                "unknown",
                if kind == "directory" {
                    "sourceStreamDigest"
                } else {
                    "expectedSourceRowDigest"
                },
            ] {
                let mut extra = fields.clone();
                extra.push((key.into(), Value::Text("1".repeat(64))));
                assert_eq!(
                    request(&Value::Map(extra)).unwrap_err(),
                    CaptureError::Malformed
                );
            }
        }
        assert_eq!(
            capture_input_request(&vec![0; MAX_CAPTURE_FRAME_BYTES + 1]).unwrap_err(),
            CaptureError::Limit
        );
    }
    #[test]
    fn capture_requests_refuse_aliases_nesting_digest_shape_and_duplicate_fields() {
        let Value::Map(fields) = request_value("directory") else {
            unreachable!()
        };
        for (key, values) in [
            ("root", vec!["/", "relative", "/tmp/../escape", "/tmp//a"]),
            (
                "sourcePath",
                vec![
                    "",
                    "/absolute",
                    "a/../b",
                    "a\\b",
                    "overlay.cbor",
                    "OVERLAY.cbor",
                    "overlay.cbor/child",
                ],
            ),
            (
                "overlayPath",
                vec!["source/child", "source", "carrier.cbor/child"],
            ),
            (
                "carrierPath",
                vec!["source/child", "source", "overlay.cbor/child"],
            ),
        ] {
            for value in values {
                let mut bad = fields.clone();
                bad.iter_mut().find(|(name, _)| name == key).unwrap().1 = Value::Text(value.into());
                assert_eq!(
                    request(&Value::Map(bad)).unwrap_err(),
                    CaptureError::Path,
                    "{key}={value}"
                );
            }
        }
        for digest in [
            "0".repeat(64),
            "A".repeat(64),
            "1".repeat(63),
            "g".repeat(64),
        ] {
            let mut bad = fields.clone();
            bad.iter_mut()
                .find(|(name, _)| name == "overlayByteDigest")
                .unwrap()
                .1 = Value::Text(digest);
            assert_eq!(
                request(&Value::Map(bad)).unwrap_err(),
                CaptureError::Malformed
            );
        }
        let mut encoded: Vec<_> = fields
            .iter()
            .map(|(key, value)| {
                (
                    encode_bounded(&Value::Text(key.clone()), CAPTURE_FRAME_LIMITS).unwrap(),
                    encode_bounded(value, CAPTURE_FRAME_LIMITS).unwrap(),
                )
            })
            .collect();
        encoded.sort_by(|a, b| a.0.cmp(&b.0));
        let mut duplicate = vec![0xa0 | (encoded.len() as u8 + 1)];
        for (index, (key, value)) in encoded.iter().enumerate() {
            duplicate.extend(key);
            duplicate.extend(value);
            if index == 0 {
                duplicate.extend(key);
                duplicate.extend(value);
            }
        }
        assert_eq!(
            capture_input_request(&duplicate).unwrap_err(),
            CaptureError::Malformed
        );
    }
    fn sum_header(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }
    fn tar(rows: &[(&str, u32, &[u8])], gnu: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, mode, bytes) in rows {
            let mut header = [0u8; 512];
            let name = format!("{PREFIX}{path}");
            header[..name.len()].copy_from_slice(name.as_bytes());
            header[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
            header[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
            header[156] = b'0';
            header[257..265].copy_from_slice(if gnu { b"ustar  \0" } else { b"ustar\000" });
            sum_header(&mut header);
            out.extend_from_slice(&header);
            out.extend_from_slice(bytes);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.resize(out.len() + 1024, 0);
        out
    }
    fn capture(bytes: &[u8]) -> Result<CapturedSourceRows, CaptureError> {
        capture_archive(bytes, ArchiveFormat::Tar, &byte_digest(bytes))
    }
    #[test]
    fn directory_rows_and_both_tar_headers_share_exact_mode_sensitive_identity() {
        let rows = [
            ("z", 0o755, b"last".as_slice()),
            ("a", 0o644, b"first".as_slice()),
        ];
        let mut directory = SourceRowsBuilder::new();
        for (path, mode, bytes) in &rows {
            directory
                .push((*path).into(), *mode, bytes.to_vec())
                .unwrap();
        }
        let directory = directory.finish().unwrap();
        for gnu in [false, true] {
            let archive = capture(&tar(&rows, gnu)).unwrap();
            assert_eq!(archive.row_digest(), directory.row_digest());
            assert_eq!(archive.byte_length(), 9);
            assert_eq!(archive.files()[0].path(), "a");
            assert_eq!(archive.files()[0].bytes(), b"first");
        }
        let mode_changed =
            capture(&tar(&[("z", 0o644, b"last"), ("a", 0o644, b"first")], true)).unwrap();
        assert_ne!(mode_changed.row_digest(), directory.row_digest());
        let value = Value::Map(vec![
            ("schema".into(), Value::Text(ROW_SCHEMA.into())),
            ("version".into(), Value::Unsigned(1)),
            ("packageId".into(), Value::Text(PACKAGE.into())),
            (
                "files".into(),
                Value::Array(
                    directory
                        .files
                        .iter()
                        .map(CapturedSourceFile::metadata)
                        .collect(),
                ),
            ),
        ]);
        let mut preimage = ROW_DOMAIN.to_vec();
        preimage.extend_from_slice(&encode_bounded(&value, CAPTURE_ROWS_LIMITS).unwrap());
        assert_eq!(byte_digest(&preimage), directory.row_digest());
    }
    #[test]
    fn directory_admission_rejects_aliases_modes_prefixes_and_reserved_paths() {
        for path in ["", "/abs", "a/../b", "a\\b", ".cargo-checksum.json", "é"] {
            assert!(
                SourceRowsBuilder::new()
                    .push(path.into(), 0o644, vec![])
                    .is_err()
            );
        }
        for mode in [0o1644, 0o2644, 0o4644, 0o100644] {
            assert_eq!(
                SourceRowsBuilder::new().push("a".into(), mode, vec![]),
                Err(CaptureError::Type)
            );
        }
        for (first, second) in [
            ("a", "a"),
            ("a", "A"),
            ("a", "a/b"),
            ("a/b", "a"),
            ("A/a", "a/b"),
        ] {
            let mut builder = SourceRowsBuilder::new();
            builder.push(first.into(), 0o644, vec![]).unwrap();
            assert_eq!(
                builder.push(second.into(), 0o644, vec![]),
                Err(CaptureError::Path)
            );
            assert_eq!(
                builder.finish().unwrap().files().len(),
                1,
                "failed insert must be atomic"
            );
        }
    }
    #[test]
    fn archive_types_extensions_checksums_padding_and_trailing_archives_refuse() {
        let valid = tar(&[("a", 0o644, b"data")], true);
        for end in [0, 1, 511, 512, 515, 1023, 1024, 1535, 1536, 2047] {
            assert!(capture(&valid[..end]).is_err(), "prefix {end}");
        }
        for kind in [b'1', b'2', b'3', b'4', b'5', b'6', b'S', b'x', b'g', b'L'] {
            let mut bad = valid.clone();
            bad[156] = kind;
            sum_header(&mut bad[..512]);
            assert_eq!(capture(&bad).unwrap_err(), CaptureError::Type);
        }
        for index in [0, 100, 124, 257, 345, 500] {
            let mut bad = valid.clone();
            bad[index] = 0xff;
            sum_header(&mut bad[..512]);
            assert!(capture(&bad).is_err());
        }
        let mut padding = valid.clone();
        padding[516] = 1;
        assert!(capture(&padding).is_err());
        let mut trailing = valid.clone();
        trailing.extend_from_slice(&valid);
        assert!(capture(&trailing).is_err());
        let mut partial_zero = valid.clone();
        partial_zero.push(0);
        assert!(capture(&partial_zero).is_err());
        let mut extra_zero = valid.clone();
        extra_zero.extend_from_slice(&[0; 512]);
        assert!(capture(&extra_zero).is_ok());
        assert_eq!(
            capture_archive(&valid, ArchiveFormat::TarGzip, &byte_digest(&valid)).unwrap_err(),
            CaptureError::Malformed
        );
        assert_eq!(
            capture_archive(&valid, ArchiveFormat::Tar, &"a".repeat(64)).unwrap_err(),
            CaptureError::Integrity
        );
    }
    #[test]
    fn maximum_row_count_and_path_metadata_match_the_canonical_encoder() {
        // 4096-byte names, shared ancestors, distinct leaves: exercise the actual
        // 20MiB metadata profile rather than testing only tiny rows at maximum count.
        let prefix = format!(
            "{}{}/",
            format!("{}/", "a".repeat(255)).repeat(15),
            "b".repeat(250)
        );
        let mut builder = SourceRowsBuilder::new();
        for index in 0..MAX_SOURCE_FILES {
            let path = format!("{prefix}{index:05}");
            assert_eq!(path.len(), 4096);
            builder.push(path, 0o777, vec![]).unwrap();
        }
        assert_eq!(
            builder.push("overflow".into(), 0o644, vec![]),
            Err(CaptureError::Limit)
        );
        let rows = builder.finish().unwrap();
        assert_eq!(rows.files().len(), MAX_SOURCE_FILES);
        let value = Value::Map(vec![
            ("schema".into(), Value::Text(ROW_SCHEMA.into())),
            ("version".into(), Value::Unsigned(1)),
            ("packageId".into(), Value::Text(PACKAGE.into())),
            (
                "files".into(),
                Value::Array(
                    rows.files
                        .iter()
                        .map(CapturedSourceFile::metadata)
                        .collect(),
                ),
            ),
        ]);
        let encoded = encode_bounded(&value, CAPTURE_ROWS_LIMITS).unwrap();
        assert!(encoded.len() > 16 * 1024 * 1024);
        let mut expected = Sha256State::new();
        expected.update(ROW_DOMAIN);
        expected.update(&encoded);
        let expected: String = expected
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(rows.row_digest(), expected);
    }
    #[test]
    fn directory_depth_components_containers_and_payload_caps_are_inclusive() {
        assert!(validate_source_path(&vec!["a"; 32].join("/")).is_ok());
        assert_eq!(
            validate_source_path(&vec!["a"; 33].join("/")),
            Err(CaptureError::Limit)
        );
        assert!(validate_source_path(&"a".repeat(255)).is_ok());
        assert_eq!(
            validate_source_path(&"a".repeat(256)),
            Err(CaptureError::Limit)
        );
        let mut containers = SourceRowsBuilder::new();
        for index in 0..2730 {
            containers
                .push(format!("d{index}/b/c/file"), 0, vec![])
                .unwrap();
        }
        containers.push("last/b/file".into(), 0, vec![]).unwrap();
        assert_eq!(containers.directories, MAX_DIRECTORIES);
        assert_eq!(
            containers.push("excess/file".into(), 0, vec![]),
            Err(CaptureError::Limit)
        );
        containers.push("last/b/other".into(), 0, vec![]).unwrap();
        let mut payload = SourceRowsBuilder::new();
        assert_eq!(
            payload.plan("excess", 0, MAX_FILE_BYTES + 1).unwrap_err(),
            CaptureError::Limit
        );
        for index in 0..8 {
            payload
                .push(format!("f{index}"), 0o644, vec![0; MAX_FILE_BYTES])
                .unwrap();
        }
        assert_eq!(payload.remaining_file_bytes(), 0);
        assert_eq!(
            payload.push("excess".into(), 0, vec![0]),
            Err(CaptureError::Limit)
        );
        payload.push("empty".into(), 0, vec![]).unwrap();
        assert_eq!(payload.finish().unwrap().byte_length(), MAX_SOURCE_BYTES);
    }
    #[test]
    fn tar_chunk_boundaries_do_not_change_identity_or_hide_invalid_names() {
        let valid = tar(&[("a", 0o644, b"data"), ("b/c", 0o755, b"second")], false);
        let expected = capture(&valid).unwrap();
        for size in [1, 7, 511, 512, 513, 8192] {
            let mut parser = TarParser::new();
            for chunk in valid.chunks(size) {
                parser.write(chunk).unwrap();
            }
            assert_eq!(parser.finish().unwrap().row_digest(), expected.row_digest());
        }
        for index in [0, 345] {
            let mut bad = valid.clone();
            bad[index] = 0xff;
            sum_header(&mut bad[..512]);
            assert_eq!(capture(&bad).unwrap_err(), CaptureError::Path);
        }
        let mut too_large = valid[..512].to_vec();
        too_large[124..136].copy_from_slice(format!("{:011o}\0", MAX_FILE_BYTES + 1).as_bytes());
        sum_header(&mut too_large);
        assert_eq!(capture(&too_large).unwrap_err(), CaptureError::Limit);
    }
    #[test]
    fn actual_pinned_gnu_gzip_source_is_fully_consumed() {
        let bytes = include_bytes!("../../../p2-crypto-crates/curve25519-dalek-5.0.0.crate");
        let captured = capture_archive(
            bytes,
            ArchiveFormat::TarGzip,
            "b5eed333089e2e1c1ac8c6c0398e5e2497b4c9926ca6d0365ed1e099afa5bc23",
        )
        .unwrap();
        assert_eq!(captured.files().len(), 74);
        assert_eq!(captured.byte_length(), 1_437_834);
        assert_eq!(
            captured
                .files()
                .iter()
                .filter(|file| file.mode() == 0o755)
                .count(),
            1
        );
        assert!(
            captured
                .files()
                .iter()
                .any(|file| file.path() == "Cargo.toml")
        );
        let mut corrupted = bytes.to_vec();
        let at = corrupted.len() - 8;
        corrupted[at] ^= 1;
        assert_eq!(
            capture_archive(&corrupted, ArchiveFormat::TarGzip, &byte_digest(&corrupted))
                .unwrap_err(),
            CaptureError::Integrity
        );
    }
}
