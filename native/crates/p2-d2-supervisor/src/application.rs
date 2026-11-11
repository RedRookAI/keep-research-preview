#![forbid(unsafe_code)]

//! Explicit operator-selected publication into a separate owned workspace.
use super::{CapturedPatchInputs, capture_io, capture_patch_inputs_with_archive};
use keep_native_linux_abi::{FileIdentity, PinnedDirectory, PinnedRegularFile};
use keep_native_protocol::patch_application::{ApplicationEvidence, apply_snapshot};
use keep_native_protocol::patch_capture::{
    CaptureError, CaptureSource, MAX_INPUT_BYTES, byte_digest, capture_input_request,
    validate_source_path,
};
use keep_native_protocol::{Limits, Value, decode_canonical, encode_bounded};
use std::io::Write;
use std::path::Path;

pub struct PublishedApplication {
    captured: CapturedPatchInputs,
    audit: Vec<u8>,
    review: Vec<u8>,
    evidence: ApplicationEvidence,
}
impl PublishedApplication {
    pub fn write_response(&self, out: &mut impl Write) -> Result<(), CaptureError> {
        self.captured.write_extended_response(
            out,
            &[
                ("audit", &self.audit),
                ("review", &self.review),
                ("evidence", &self.evidence.canonical),
            ],
        )
    }
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, CaptureError> {
    match value.field(key) {
        Some(Value::Text(s)) => Ok(s),
        _ => Err(CaptureError::Malformed),
    }
}
fn bytes<'a>(value: &'a Value, key: &str) -> Result<&'a [u8], CaptureError> {
    match value.field(key) {
        Some(Value::Bytes(s)) => Ok(s),
        _ => Err(CaptureError::Malformed),
    }
}
fn stage(dir: &PinnedDirectory, name: &str, value: &[u8]) -> Result<(), CaptureError> {
    dir.stage_owned_file(name, value, MAX_INPUT_BYTES as u64, 0o400)
        .map_err(capture_io)?;
    Ok(())
}
fn node_same(left: &PinnedDirectory, right: &PinnedDirectory) -> bool {
    left.identity().device == right.identity().device
        && left.identity().inode == right.identity().inode
}

#[derive(Default)]
struct StageManifest {
    files: std::collections::BTreeMap<String, (FileIdentity, String)>,
    directories: std::collections::BTreeMap<String, FileIdentity>,
}
fn tracked_file(
    dir: &PinnedDirectory,
    name: &str,
    bytes: &[u8],
    path: &str,
    manifest: &mut StageManifest,
) -> Result<(), CaptureError> {
    let captured = dir
        .stage_owned_file(name, bytes, MAX_INPUT_BYTES as u64, 0o400)
        .map_err(capture_io)?;
    manifest.files.insert(
        path.into(),
        (captured.identity().clone(), byte_digest(bytes)),
    );
    Ok(())
}
fn verify_stage(
    parent: &PinnedDirectory,
    name: &str,
    held: &PinnedDirectory,
    manifest: &StageManifest,
) -> Result<(), CaptureError> {
    parent.verify_child(name, held).map_err(capture_io)?;
    let root = parent.open_child_directory(name).map_err(capture_io)?;
    let mut seen_files = 0;
    let mut seen_directories = 0;
    fn walk(
        dir: &PinnedDirectory,
        prefix: &str,
        manifest: &StageManifest,
        files: &mut usize,
        directories: &mut usize,
    ) -> Result<(), CaptureError> {
        let expected = manifest
            .directories
            .get(prefix)
            .ok_or(CaptureError::Integrity)?;
        if dir.identity().device != expected.device
            || dir.identity().inode != expected.inode
            || dir.identity().uid != expected.uid
            || dir.identity().gid != expected.gid
            || dir.identity().mode & 0o7777 != 0o500
        {
            return Err(CaptureError::Race);
        }
        *directories += 1;
        for entry in dir.inventory(16_384, 16_384 * 255).map_err(capture_io)? {
            let path = if prefix.is_empty() {
                entry.name.clone()
            } else {
                format!("{prefix}/{}", entry.name)
            };
            if manifest.directories.contains_key(&path) {
                let child = dir.open_child_directory(&entry.name).map_err(capture_io)?;
                walk(&child, &path, manifest, files, directories)?;
            } else {
                let (identity, digest) =
                    manifest.files.get(&path).ok_or(CaptureError::Integrity)?;
                if &entry.identity != identity {
                    return Err(CaptureError::Race);
                }
                let file = dir
                    .capture_regular_file(&entry.name, MAX_INPUT_BYTES as u64)
                    .map_err(capture_io)?;
                if file.identity() != identity || byte_digest(file.bytes()) != *digest {
                    return Err(CaptureError::Integrity);
                }
                *files += 1;
            }
        }
        Ok(())
    }
    walk(&root, "", manifest, &mut seen_files, &mut seen_directories)?;
    if seen_files != manifest.files.len() || seen_directories != manifest.directories.len() {
        return Err(CaptureError::Integrity);
    }
    Ok(())
}

fn stage_tree(
    root: &PinnedDirectory,
    evidence: &ApplicationEvidence,
    manifest: &mut StageManifest,
) -> Result<(), CaptureError> {
    let mut directories = std::collections::BTreeMap::new();
    for file in evidence.result.files() {
        let mut parts: Vec<_> = file.path.split('/').collect();
        let name = parts.pop().ok_or(CaptureError::Path)?;
        let mut prefix = String::new();
        for part in parts {
            let next = if prefix.is_empty() {
                part.to_owned()
            } else {
                format!("{prefix}/{part}")
            };
            if !directories.contains_key(&next) {
                let parent = if prefix.is_empty() {
                    root
                } else {
                    directories.get(&prefix).ok_or(CaptureError::Io)?
                };
                let child = parent.create_owned_directory(part).map_err(capture_io)?;
                manifest
                    .directories
                    .insert(format!("tree/{next}"), child.identity().clone());
                directories.insert(next.clone(), child);
            }
            prefix = next;
        }
        let parent = if prefix.is_empty() {
            root
        } else {
            directories.get(&prefix).ok_or(CaptureError::Io)?
        };
        tracked_file(
            parent,
            name,
            evidence
                .result
                .file_bytes(&file.path)
                .ok_or(CaptureError::Integrity)?,
            &format!("tree/{}", file.path),
            manifest,
        )?;
    }
    tracked_file(
        root,
        ".cargo-checksum.json",
        &evidence.checksum,
        "tree/.cargo-checksum.json",
        manifest,
    )?;
    for (_, directory) in directories.iter().rev() {
        directory.seal_owned_directory().map_err(capture_io)?;
    }
    root.seal_owned_directory().map_err(capture_io)
}

pub fn publish_application(request_bytes: &[u8]) -> Result<PublishedApplication, CaptureError> {
    let value =
        decode_canonical(request_bytes, Limits::WIRE).map_err(|_| CaptureError::Malformed)?;
    let keys = [
        "schema",
        "version",
        "captureRequest",
        "auditPath",
        "auditByteDigest",
        "reviewPath",
        "reviewByteDigest",
        "outputRoot",
        "attemptId",
    ];
    let Value::Map(rows) = &value else {
        return Err(CaptureError::Malformed);
    };
    if rows.len() != keys.len()
        || keys.iter().any(|key| value.field(key).is_none())
        || value.field("schema") != Some(&Value::Text("keep.patch-application-request".into()))
        || value.field("version") != Some(&Value::Unsigned(1))
    {
        return Err(CaptureError::Malformed);
    }
    let request = capture_input_request(bytes(&value, "captureRequest")?)?;
    if !matches!(request.source(), CaptureSource::Archive { .. }) {
        return Err(CaptureError::Unsupported);
    }
    let audit_path = string(&value, "auditPath")?;
    let review_path = string(&value, "reviewPath")?;
    validate_source_path(audit_path)?;
    validate_source_path(review_path)?;
    let paths = [
        request.source_path(),
        request.overlay_path(),
        request.carrier_path(),
        audit_path,
        review_path,
    ];
    for (i, a) in paths.iter().enumerate() {
        for b in paths.iter().skip(i + 1) {
            let a = a.to_ascii_lowercase();
            let b = b.to_ascii_lowercase();
            if a == b || a.starts_with(&format!("{b}/")) || b.starts_with(&format!("{a}/")) {
                return Err(CaptureError::Path);
            }
        }
    }
    let output_path = string(&value, "outputRoot")?;
    let attempt_id = string(&value, "attemptId")?;
    validate_source_path(attempt_id)?;
    if attempt_id.contains('/')
        || attempt_id.len() > 128
        || output_path == request.root()
        || output_path.starts_with(&format!("{}/", request.root()))
        || request.root().starts_with(&format!("{output_path}/"))
    {
        return Err(CaptureError::Path);
    }
    let source_root = PinnedDirectory::open(Path::new(request.root())).map_err(capture_io)?;
    let output =
        PinnedDirectory::open_owned_workspace(Path::new(output_path)).map_err(capture_io)?;
    if node_same(&source_root, &output) {
        return Err(CaptureError::Path);
    }
    let attempt = output
        .create_owned_directory(attempt_id)
        .map_err(capture_io)?;
    let request_digest = {
        let mut preimage = b"keep.patch-application-request/v1\0".to_vec();
        preimage.extend_from_slice(request_bytes);
        byte_digest(&preimage)
    };
    stage(&attempt, "request.cbor", request_bytes)?;
    let ledger = |status: &str, code: &str| {
        encode_bounded(
            &Value::Map(vec![
                (
                    "schema".into(),
                    Value::Text("keep.patch-application-attempt".into()),
                ),
                ("version".into(), Value::Unsigned(1)),
                ("requestDigest".into(), Value::Text(request_digest.clone())),
                ("outcome".into(), Value::Text(status.into())),
                ("code".into(), Value::Text(code.into())),
                ("authorizing".into(), Value::Bool(false)),
            ]),
            Limits::WIRE,
        )
        .map_err(|_| CaptureError::Limit)
    };
    stage(&attempt, "attempt.cbor", &ledger("attempted", "PENDING")?)?;
    attempt.sync_directory().map_err(capture_io)?;
    output.sync_directory().map_err(capture_io)?;
    let mut dispatched = false;
    let result = (|| {
        let held: Vec<(&str, PinnedRegularFile)> = paths
            .iter()
            .map(|path| {
                source_root
                    .open_regular_file(path, MAX_INPUT_BYTES as u64)
                    .map(|f| (*path, f))
                    .map_err(capture_io)
            })
            .collect::<Result<_, _>>()?;
        let audit = source_root
            .capture_regular_file(audit_path, 1024 * 1024)
            .map_err(capture_io)?;
        let review = source_root
            .capture_regular_file(review_path, 65_536)
            .map_err(capture_io)?;
        if byte_digest(audit.bytes()) != string(&value, "auditByteDigest")?
            || byte_digest(review.bytes()) != string(&value, "reviewByteDigest")?
        {
            return Err(CaptureError::Integrity);
        }
        let captured = capture_patch_inputs_with_archive(
            capture_input_request(bytes(&value, "captureRequest")?)?,
            true,
        )?;
        let staging = attempt
            .create_owned_directory("staging")
            .map_err(capture_io)?;
        let mut manifest = StageManifest::default();
        manifest
            .directories
            .insert("".into(), staging.identity().clone());
        let inputs = staging
            .create_owned_directory("inputs")
            .map_err(capture_io)?;
        manifest
            .directories
            .insert("inputs".into(), inputs.identity().clone());
        tracked_file(
            &inputs,
            "source.archive",
            captured
                .archive_bytes
                .as_ref()
                .ok_or(CaptureError::Unsupported)?,
            "inputs/source.archive",
            &mut manifest,
        )?;
        tracked_file(
            &inputs,
            "overlay.cbor",
            captured.overlay.canonical_bytes(),
            "inputs/overlay.cbor",
            &mut manifest,
        )?;
        tracked_file(
            &inputs,
            "carriers.cbor",
            captured.carrier.canonical_bytes(),
            "inputs/carriers.cbor",
            &mut manifest,
        )?;
        tracked_file(
            &inputs,
            "audit.cbor",
            audit.bytes(),
            "inputs/audit.cbor",
            &mut manifest,
        )?;
        tracked_file(
            &inputs,
            "review.cbor",
            review.bytes(),
            "inputs/review.cbor",
            &mut manifest,
        )?;
        inputs.seal_owned_directory().map_err(capture_io)?;
        let evidence = apply_snapshot(
            &captured.source,
            &captured.overlay,
            &captured.carrier,
            audit.bytes(),
            review.bytes(),
            &request_digest,
        )?;
        let tree = staging.create_owned_directory("tree").map_err(capture_io)?;
        manifest
            .directories
            .insert("tree".into(), tree.identity().clone());
        stage_tree(&tree, &evidence, &mut manifest)?;
        tracked_file(
            &staging,
            "evidence.cbor",
            &evidence.canonical,
            "evidence.cbor",
            &mut manifest,
        )?;
        tracked_file(
            &staging,
            "result-tree.cbor",
            evidence.result.canonical_bytes(),
            "result-tree.cbor",
            &mut manifest,
        )?;
        staging.seal_owned_directory().map_err(capture_io)?;
        verify_stage(&attempt, "staging", &staging, &manifest)?;
        // Reopen only for identity checks; no source/carrier payload is reread.
        let current_source =
            PinnedDirectory::open(Path::new(captured.request.root())).map_err(capture_io)?;
        if current_source.identity() != source_root.identity() {
            return Err(CaptureError::Race);
        }
        for (path, original) in &held {
            let current = source_root
                .open_regular_file(path, MAX_INPUT_BYTES as u64)
                .map_err(capture_io)?;
            if current.identity() != original.identity() {
                return Err(CaptureError::Race);
            }
        }
        let current_output =
            PinnedDirectory::open_owned_workspace(Path::new(output_path)).map_err(capture_io)?;
        if !node_same(&current_output, &output) {
            return Err(CaptureError::Race);
        }
        output
            .verify_child(attempt_id, &attempt)
            .map_err(capture_io)?;
        if let Err(error) = attempt.publish_owned_directory("staging", &staging, "candidate") {
            dispatched = error.dispatched;
            return Err(capture_io(error.source));
        }
        dispatched = true;
        verify_stage(&attempt, "candidate", &staging, &manifest)?;
        let after_output =
            PinnedDirectory::open_owned_workspace(Path::new(output_path)).map_err(capture_io)?;
        if !node_same(&after_output, &output) {
            return Err(CaptureError::Race);
        }
        output
            .verify_child(attempt_id, &attempt)
            .map_err(capture_io)?;
        stage(&attempt, "published.cbor", &ledger("published", "OK")?)?;
        attempt.sync_directory().map_err(capture_io)?;
        Ok(PublishedApplication {
            captured,
            audit: audit.into_bytes(),
            review: review.into_bytes(),
            evidence,
        })
    })();
    if let Err(error) = result {
        let status = if dispatched { "unknown" } else { "failed" };
        // Original intent remains durable even when recording an outcome also fails.
        if let Ok(record) = ledger(status, error.code()) {
            let _ = stage(&attempt, "outcome.cbor", &record);
            let _ = attempt.sync_directory();
        }
        return Err(error);
    }
    result
}
