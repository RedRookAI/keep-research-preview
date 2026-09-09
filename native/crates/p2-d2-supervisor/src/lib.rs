#![forbid(unsafe_code)]

//! Native patch input acquisition. Returned rows are inert data, not installation,
//! signature, build or launch authority. Unsafe syscalls stay in the existing ABI.

use keep_native_linux_abi::{CaptureIoFailure, PinnedDirectory};
use keep_native_protocol::p2_d2::{
    MAX_CARRIER_SET_ENCODED_BYTES, ValidatedPatchByteCarrierSet, ValidatedPatchOverlayPlan,
    capture_patch_byte_carrier_set, capture_patch_overlay, join_patch_application_inputs,
};
use keep_native_protocol::patch_capture::{
    CAPTURE_CHUNK_BYTES, CAPTURE_FRAME_LIMITS, CAPTURE_RESPONSE_DOMAIN, CaptureError,
    CaptureSource, CapturedSourceRows, MAX_CAPTURE_FRAMES, MAX_CAPTURE_RESPONSE_BYTES,
    MAX_DIRECTORIES, MAX_INPUT_BYTES, MAX_SOURCE_FILES, SourceRowsBuilder, ValidatedCaptureRequest,
    byte_digest, capture_archive, validate_source_mode, validate_source_path,
};
use keep_native_protocol::{Limits, Sha256State, Value, encode_bounded};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::Path;

fn capture_io(error: io::Error) -> CaptureError {
    match CaptureIoFailure::from_io(&error) {
        Some(CaptureIoFailure::Path) => CaptureError::Path,
        Some(CaptureIoFailure::Type) => CaptureError::Type,
        Some(CaptureIoFailure::Limit) => CaptureError::Limit,
        Some(CaptureIoFailure::Race) => CaptureError::Race,
        Some(CaptureIoFailure::Unsupported) => CaptureError::Unsupported,
        None => CaptureError::Io,
    }
}

const MAX_ENTRIES: usize = MAX_SOURCE_FILES + MAX_DIRECTORIES;
const MAX_NAME_BYTES: usize = MAX_ENTRIES * 255;

/// All members are owned and fully validated before construction completes.
/// Nothing in this value can install, sign, mutate, build or launch captured data.
#[derive(Debug)]
pub struct CapturedPatchInputs {
    request: ValidatedCaptureRequest,
    source: CapturedSourceRows,
    overlay: ValidatedPatchOverlayPlan,
    carrier: ValidatedPatchByteCarrierSet,
}

pub fn capture_patch_inputs(
    request: ValidatedCaptureRequest,
) -> Result<CapturedPatchInputs, CaptureError> {
    let root = PinnedDirectory::open(Path::new(request.root())).map_err(capture_io)?;
    let overlay = {
        let raw = root
            .capture_regular_file(request.overlay_path(), Limits::WIRE.max_bytes as u64)
            .map_err(capture_io)?;
        if byte_digest(raw.bytes()) != request.overlay_byte_digest() {
            return Err(CaptureError::Integrity);
        }
        capture_patch_overlay(raw.bytes()).map_err(|_| CaptureError::Malformed)?
    };
    if overlay.overlay().base_archive_digest != request.overlay_base_digest() {
        return Err(CaptureError::Integrity);
    }
    let carrier = {
        let raw = root
            .capture_regular_file(request.carrier_path(), MAX_CARRIER_SET_ENCODED_BYTES as u64)
            .map_err(capture_io)?;
        if byte_digest(raw.bytes()) != request.carrier_byte_digest() {
            return Err(CaptureError::Integrity);
        }
        capture_patch_byte_carrier_set(raw.bytes()).map_err(|_| CaptureError::Malformed)?
    }; // Release original carrier bytes before acquiring any source payload.
    join_patch_application_inputs(&overlay, &carrier).map_err(|_| CaptureError::Integrity)?;
    let source = match request.source() {
        CaptureSource::Archive {
            format,
            stream_digest,
        } => {
            let raw = root
                .capture_regular_file(request.source_path(), MAX_INPUT_BYTES as u64)
                .map_err(capture_io)?;
            capture_archive(raw.bytes(), *format, stream_digest)?
        } // Compressed input/FD drop here, before response emission.
        CaptureSource::Directory {
            expected_row_digest,
            ..
        } => {
            let mut parts = request.source_path().split('/');
            let mut directory = root
                .open_child_directory(parts.next().ok_or(CaptureError::Path)?)
                .map_err(capture_io)?;
            for part in parts {
                directory = directory.open_child_directory(part).map_err(capture_io)?;
            }
            capture_source_directory(&directory, expected_row_digest)?
        }
    };
    let result = CapturedPatchInputs {
        request,
        source,
        overlay,
        carrier,
    };
    result.check_response_budget()?;
    Ok(result)
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
fn number(value: usize) -> Value {
    Value::Unsigned(value as u64)
}

impl CapturedPatchInputs {
    pub fn source(&self) -> &CapturedSourceRows {
        &self.source
    }
    pub fn overlay(&self) -> &ValidatedPatchOverlayPlan {
        &self.overlay
    }
    pub fn carrier(&self) -> &ValidatedPatchByteCarrierSet {
        &self.carrier
    }

    fn check_response_budget(&self) -> Result<(), CaptureError> {
        // Conservative wire upper bound, computed from validated sizes before the
        // first frame. No second serialization pass or full output buffer.
        let mut frames = 4usize; // header, two input metadata records, END
        let mut metadata = 2048usize; // bounds fixed header/input/END text and hashes
        for file in self.source.files() {
            frames += 1 + file.bytes().len().div_ceil(CAPTURE_CHUNK_BYTES);
            metadata += file.path().len() + 160;
        }
        let overlay = self.overlay.canonical_bytes().len();
        let carrier = self.carrier.canonical_bytes().len();
        frames += overlay.div_ceil(CAPTURE_CHUNK_BYTES) + carrier.div_ceil(CAPTURE_CHUNK_BYTES);
        let bytes = self.source.byte_length() + overlay + carrier + metadata + frames * 128;
        if frames > MAX_CAPTURE_FRAMES || bytes > MAX_CAPTURE_RESPONSE_BYTES {
            return Err(CaptureError::Limit);
        }
        Ok(())
    }

    /// Emits only the closed, non-authorizing capture protocol. Transport failure
    /// may leave partial bytes; the SDK must withhold all values until END/EOF/exit0.
    pub fn write_response(&self, output: &mut impl Write) -> Result<(), CaptureError> {
        let request = &self.request;
        let mut header = vec![
            ("record".into(), text("header")),
            ("schema".into(), text("keep.patch-input-result")),
            ("version".into(), Value::Unsigned(1)),
            ("requestDigest".into(), text(request.digest())),
            ("sourceKind".into(), text(request.source_kind())),
            ("sourceRowDigest".into(), text(self.source.row_digest())),
            (
                "overlayTypedDigest".into(),
                text(self.overlay.patch_overlay_digest()),
            ),
            (
                "carrierTypedDigest".into(),
                text(self.carrier.patch_byte_carrier_set_digest()),
            ),
            (
                "overlayByteDigest".into(),
                text(request.overlay_byte_digest()),
            ),
            (
                "carrierByteDigest".into(),
                text(request.carrier_byte_digest()),
            ),
            ("sourceCount".into(), number(self.source.files().len())),
            ("sourceBytes".into(), number(self.source.byte_length())),
            (
                "overlayBytes".into(),
                number(self.overlay.canonical_bytes().len()),
            ),
            (
                "carrierBytes".into(),
                number(self.carrier.canonical_bytes().len()),
            ),
        ];
        header.push(match request.source() {
            CaptureSource::Directory {
                declared_base_archive_digest,
                ..
            } => (
                "declaredBaseArchiveDigest".into(),
                text(declared_base_archive_digest),
            ),
            CaptureSource::Archive { stream_digest, .. } => {
                ("sourceStreamDigest".into(), text(stream_digest))
            }
        });
        let mut writer = ResponseWriter::new(output);
        writer.frame(Value::Map(header))?;
        for (index, file) in self.source.files().iter().enumerate() {
            writer.frame(Value::Map(vec![
                ("record".into(), text("source-row")),
                ("index".into(), number(index)),
                ("path".into(), text(file.path())),
                ("mode".into(), Value::Unsigned(file.mode() as u64)),
                ("byteLength".into(), number(file.bytes().len())),
                ("byteDigest".into(), text(file.byte_digest())),
            ]))?;
            writer.chunks(file.bytes())?;
        }
        for (role, bytes, digest) in [
            (
                "overlay",
                self.overlay.canonical_bytes(),
                request.overlay_byte_digest(),
            ),
            (
                "carrier",
                self.carrier.canonical_bytes(),
                request.carrier_byte_digest(),
            ),
        ] {
            writer.frame(Value::Map(vec![
                ("record".into(), text("input")),
                ("role".into(), text(role)),
                ("byteLength".into(), number(bytes.len())),
                ("byteDigest".into(), text(digest)),
            ]))?;
            writer.chunks(bytes)?;
        }
        writer.finish()
    }
}

struct ResponseWriter<'a, W: Write> {
    output: &'a mut W,
    hash: Sha256State,
    frames: usize,
    bytes: usize,
}
impl<'a, W: Write> ResponseWriter<'a, W> {
    fn new(output: &'a mut W) -> Self {
        let mut hash = Sha256State::new();
        hash.update(CAPTURE_RESPONSE_DOMAIN);
        Self {
            output,
            hash,
            frames: 0,
            bytes: 0,
        }
    }
    fn frame(&mut self, value: Value) -> Result<(), CaptureError> {
        let bytes =
            encode_bounded(&value, CAPTURE_FRAME_LIMITS).map_err(|_| CaptureError::Limit)?;
        self.frames += 1;
        self.bytes = self
            .bytes
            .checked_add(bytes.len() + 4)
            .ok_or(CaptureError::Limit)?;
        if self.frames > MAX_CAPTURE_FRAMES || self.bytes > MAX_CAPTURE_RESPONSE_BYTES {
            return Err(CaptureError::Limit);
        }
        let length = (bytes.len() as u32).to_be_bytes();
        self.hash.update(&length);
        self.hash.update(&bytes);
        self.output
            .write_all(&length)
            .map_err(|_| CaptureError::Io)?;
        self.output.write_all(&bytes).map_err(|_| CaptureError::Io)
    }
    fn chunks(&mut self, bytes: &[u8]) -> Result<(), CaptureError> {
        for (sequence, part) in bytes.chunks(CAPTURE_CHUNK_BYTES).enumerate() {
            self.frame(Value::Map(vec![
                ("record".into(), text("chunk")),
                ("sequence".into(), number(sequence)),
                ("bytes".into(), Value::Bytes(part.to_vec())),
            ]))?;
        }
        Ok(())
    }
    fn finish(mut self) -> Result<(), CaptureError> {
        // Commit all PRECEDING framed bytes; END's own bytes are excluded.
        let committed = std::mem::replace(&mut self.hash, Sha256State::new()).finalize();
        let digest: String = committed.iter().map(|byte| format!("{byte:02x}")).collect();
        self.frame(Value::Map(vec![
            ("record".into(), text("end")),
            ("responseDigest".into(), text(&digest)),
        ]))?;
        self.output.flush().map_err(|_| CaptureError::Io)
    }
}

fn capture_directory(
    directory: &PinnedDirectory,
    prefix: &str,
    depth: usize,
    directories: &mut usize,
    rows: &mut SourceRowsBuilder,
) -> Result<(), CaptureError> {
    let before = directory
        .inventory(MAX_ENTRIES, MAX_NAME_BYTES)
        .map_err(capture_io)?;
    let mut folded = BTreeSet::new();
    for entry in &before {
        if !folded.insert(entry.name.to_ascii_lowercase()) {
            return Err(CaptureError::Path);
        }
        let path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        validate_source_path(&path)?;
        // These are POSIX file type bits, not permission bits. No dependency edge
        // to libc is needed; metadata values are supplied by the existing ABI.
        match entry.identity.mode & 0o170000 {
            0o040000 => {
                *directories = directories
                    .checked_add(1)
                    .filter(|count| *count <= MAX_DIRECTORIES)
                    .ok_or(CaptureError::Limit)?;
                if depth >= 32 {
                    return Err(CaptureError::Limit);
                }
                let child = directory
                    .open_child_directory(&entry.name)
                    .map_err(capture_io)?;
                if child.identity() != &entry.identity {
                    return Err(CaptureError::Race);
                }
                capture_directory(&child, &path, depth + 1, directories, rows)?;
            }
            0o100000 => {
                // Check the FULL special/permission bits before projecting the
                // admitted 0777 row mode. Never erase setuid/setgid/sticky first.
                validate_source_mode(entry.identity.mode & 0o7777)?;
                if entry.identity.links != 1 {
                    return Err(CaptureError::Type);
                }
                rows.check_file(
                    &path,
                    entry.identity.mode & 0o777,
                    usize::try_from(entry.identity.size).map_err(|_| CaptureError::Limit)?,
                )?;
                let file = directory
                    .capture_regular_file(&entry.name, rows.remaining_file_bytes() as u64)
                    .map_err(capture_io)?;
                if file.identity() != &entry.identity {
                    return Err(CaptureError::Race);
                }
                rows.push(path, entry.identity.mode & 0o777, file.into_bytes())?;
            }
            _ => return Err(CaptureError::Type),
        }
    }
    // Timestamps are not a mutation counter: compare complete local names AND
    // inode metadata after descendant capture, including empty directories.
    let after = directory
        .inventory(MAX_ENTRIES, MAX_NAME_BYTES)
        .map_err(capture_io)?;
    if after != before {
        return Err(CaptureError::Race);
    }
    Ok(())
}

/// Captures a declared fixed content set under a held source directory. The expected
/// row hash is a consistency target, not release provenance or an atomic live-tree
/// snapshot claim. No partial rows escape a failed inventory/read/hash comparison.
pub fn capture_source_directory(
    directory: &PinnedDirectory,
    expected_source_row_digest: &str,
) -> Result<CapturedSourceRows, CaptureError> {
    if expected_source_row_digest.len() != 64
        || !expected_source_row_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || expected_source_row_digest.bytes().all(|byte| byte == b'0')
    {
        return Err(CaptureError::Malformed);
    }
    let mut rows = SourceRowsBuilder::new();
    capture_directory(directory, "", 0, &mut 0, &mut rows)?;
    let rows = rows.finish()?;
    if rows.row_digest() != expected_source_row_digest {
        return Err(CaptureError::Integrity);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "keep-patch-directory-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }
    fn expected(rows: &[(&str, u32, &[u8])]) -> String {
        let mut builder = SourceRowsBuilder::new();
        for (path, mode, bytes) in rows {
            builder.push((*path).into(), *mode, bytes.to_vec()).unwrap();
        }
        builder.finish().unwrap().row_digest().into()
    }
    fn capture(root: &PathBuf, digest: &str) -> Result<CapturedSourceRows, CaptureError> {
        capture_source_directory(&PinnedDirectory::open(root).unwrap(), digest)
    }

    #[test]
    fn directory_capture_returns_exact_sorted_owned_mode_sensitive_rows() {
        let root = scratch();
        fs::create_dir(root.join("src")).unwrap();
        fs::create_dir(root.join("empty-directory")).unwrap();
        fs::write(root.join("src/lib.rs"), b"pub fn keep() {}\n").unwrap();
        fs::set_permissions(root.join("src/lib.rs"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(root.join("tool"), b"tool bytes").unwrap();
        fs::set_permissions(root.join("tool"), fs::Permissions::from_mode(0o755)).unwrap();
        let digest = expected(&[
            ("tool", 0o755, b"tool bytes"),
            ("src/lib.rs", 0o644, b"pub fn keep() {}\n"),
        ]);
        let rows = capture(&root, &digest).unwrap();
        assert_eq!(rows.files()[0].path(), "src/lib.rs");
        assert_eq!(rows.files()[1].mode(), 0o755);
        fs::write(root.join("tool"), b"replacement").unwrap();
        assert_eq!(rows.files()[1].bytes(), b"tool bytes");
        assert_eq!(
            capture(&root, &digest).unwrap_err(),
            CaptureError::Integrity
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_capture_denies_special_modes_links_checksums_and_case_aliases() {
        for mode in [0o1644, 0o2644, 0o4644] {
            let root = scratch();
            fs::write(root.join("file"), b"data").unwrap();
            fs::set_permissions(root.join("file"), fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                capture(&root, &"a".repeat(64)).unwrap_err(),
                CaptureError::Type
            );
            fs::remove_dir_all(root).unwrap();
        }
        for kind in ["symlink", "hardlink", "checksum", "case-alias", "non-ascii"] {
            let root = scratch();
            match kind {
                "symlink" => symlink("missing", root.join("alias")).unwrap(),
                "hardlink" => {
                    fs::write(root.join("file"), b"data").unwrap();
                    fs::hard_link(root.join("file"), root.join("alias")).unwrap();
                }
                "checksum" => fs::write(root.join(".cargo-checksum.json"), b"{}").unwrap(),
                "case-alias" => {
                    fs::create_dir(root.join("Empty")).unwrap();
                    fs::create_dir(root.join("empty")).unwrap();
                }
                _ => fs::write(root.join("é"), b"data").unwrap(),
            }
            let error = capture(&root, &"a".repeat(64)).unwrap_err();
            assert_eq!(
                error,
                if kind == "hardlink" {
                    CaptureError::Type
                } else {
                    CaptureError::Path
                },
                "{kind}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn directory_capture_enforces_actual_file_and_aggregate_capacities() {
        use keep_native_protocol::patch_capture::{MAX_FILE_BYTES, MAX_SOURCE_BYTES};
        let root = scratch();
        let data = vec![0x5a; MAX_FILE_BYTES];
        let mut expected_rows = SourceRowsBuilder::new();
        for index in 0..8 {
            let path = format!("f{index}");
            fs::write(root.join(&path), &data).unwrap();
            fs::set_permissions(root.join(&path), fs::Permissions::from_mode(0o644)).unwrap();
            expected_rows.push(path, 0o644, data.clone()).unwrap();
        }
        let digest = expected_rows.finish().unwrap().row_digest().to_owned();
        let captured = capture(&root, &digest).unwrap();
        assert_eq!(captured.byte_length(), MAX_SOURCE_BYTES);
        assert_eq!(captured.files().len(), 8);
        assert!(captured.files().iter().all(|file| file.bytes() == data));
        drop(captured);
        fs::write(root.join("z-excess"), [0]).unwrap();
        assert_eq!(capture(&root, &digest).unwrap_err(), CaptureError::Limit);
        // A sparse one-over member proves refusal from metadata, not after reading
        // or allocating its declared payload. No large extra disk allocation.
        fs::File::create(root.join("a-oversized"))
            .unwrap()
            .set_len((MAX_FILE_BYTES + 1) as u64)
            .unwrap();
        assert_eq!(capture(&root, &digest).unwrap_err(), CaptureError::Limit);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_capture_enforces_actual_cardinality_depth_and_container_caps() {
        let root = scratch();
        let mut builder = SourceRowsBuilder::new();
        for index in 0..MAX_SOURCE_FILES {
            let path = format!("f{index:04}");
            fs::write(root.join(&path), []).unwrap();
            fs::set_permissions(root.join(&path), fs::Permissions::from_mode(0o644)).unwrap();
            builder.push(path, 0o644, vec![]).unwrap();
        }
        let digest = builder.finish().unwrap().row_digest().to_owned();
        assert_eq!(
            capture(&root, &digest).unwrap().files().len(),
            MAX_SOURCE_FILES
        );
        fs::write(root.join("z-excess"), []).unwrap();
        assert_eq!(capture(&root, &digest).unwrap_err(), CaptureError::Limit);
        fs::remove_dir_all(root).unwrap();

        let root = scratch();
        let mut leaf = root.clone();
        for _ in 0..31 {
            leaf.push("d");
            fs::create_dir(&leaf).unwrap();
        }
        fs::write(leaf.join("file"), []).unwrap();
        fs::set_permissions(leaf.join("file"), fs::Permissions::from_mode(0o644)).unwrap();
        let path = format!("{}file", "d/".repeat(31));
        let digest = expected(&[(&path, 0o644, b"")]);
        assert_eq!(capture(&root, &digest).unwrap().files()[0].path(), path);
        fs::create_dir(leaf.join("d")).unwrap();
        fs::write(leaf.join("d/file"), []).unwrap();
        assert_eq!(capture(&root, &digest).unwrap_err(), CaptureError::Limit);
        fs::remove_dir_all(root).unwrap();

        let root = scratch();
        for index in 0..MAX_DIRECTORIES {
            fs::create_dir(root.join(format!("d{index}"))).unwrap();
        }
        assert!(capture(&root, &expected(&[])).unwrap().files().is_empty());
        fs::create_dir(root.join("z-excess")).unwrap();
        assert_eq!(
            capture(&root, &expected(&[])).unwrap_err(),
            CaptureError::Limit
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_capture_admits_empty_content_and_rejects_invalid_commitments() {
        let root = scratch();
        assert!(capture(&root, &expected(&[])).unwrap().files().is_empty());
        for digest in [
            "".to_owned(),
            "0".repeat(64),
            "A".repeat(64),
            "a".repeat(63),
        ] {
            assert_eq!(
                capture(&root, &digest).unwrap_err(),
                CaptureError::Malformed
            );
        }
        assert_eq!(
            capture(&root, &"a".repeat(64)).unwrap_err(),
            CaptureError::Integrity
        );
        fs::remove_dir_all(root).unwrap();
    }
}
