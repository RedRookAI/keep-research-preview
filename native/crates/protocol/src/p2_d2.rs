#![forbid(unsafe_code)]

//! Dependency-free, non-authorizing P2-D2 patch capture and pure application.
//! This crate accepts owned bytes and has no filesystem, process, network, build,
//! signature, admission, or launch capability.

use crate::p2_schema::canonical_relative;
use crate::{Limits, Value, decode_canonical, encode_bounded, sha256_hex};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};

pub const OVERLAY_SCHEMA: &str = "keep.p2-d2-patch-overlay";
pub const OVERLAY_PACKAGE_ID: &str = "curve25519-dalek@5.0.0";
pub const OVERLAY_DOMAIN: &[u8] = b"keep.p2-d2-patch-overlay/v1\0";
pub const MAX_OPERATIONS: usize = 256;
pub const MAX_NEW_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_AGGREGATE_NEW_BYTES: u64 = 128 * 1024 * 1024;
pub const CARRIER_SET_SCHEMA: &str = "keep.p2-d2-patch-byte-carrier-set";
pub const CARRIER_SET_DOMAIN: &[u8] = b"keep.p2-d2-patch-byte-carrier-set/v1\0";
pub const MAX_CARRIER_SET_ENCODED_BYTES: usize = 130 * 1024 * 1024;
pub const RESULT_TREE_SCHEMA: &str = "keep.p2-d2-result-tree";
pub const RESULT_TREE_DOMAIN: &[u8] = b"keep.p2-d2-result-tree/v1\0";
pub const MAX_ARCHIVE_FILES: usize = 4096;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ROOT_KEYS: &[&str] = &[
    "schema",
    "version",
    "packageId",
    "baseArchiveDigest",
    "operations",
    "rationale",
    "resultTreeDigest",
    "auditPlanDigest",
];
const OPERATION_KEYS: &[&str] = &[
    "operation",
    "path",
    "oldByteDigest",
    "newByteDigest",
    "newByteLength",
];
const CARRIER_ROOT_KEYS: &[&str] = &["schema", "version", "packageId", "entries"];
const CARRIER_ENTRY_KEYS: &[&str] = &["path", "operation", "bytes"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverlayError(pub &'static str);
impl Display for OverlayError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for OverlayError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchOperationKindV1 {
    Add,
    Delete,
    Replace,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePatchOperationV1 {
    pub operation: PatchOperationKindV1,
    pub path: String,
    pub old_byte_digest: Option<String>,
    pub new_byte_digest: Option<String>,
    pub new_byte_length: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePatchOverlayV1 {
    pub base_archive_digest: String,
    pub operations: Vec<NativePatchOperationV1>,
    pub rationale: String,
    pub result_tree_digest: String,
    pub audit_plan_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPatchOverlayPlan {
    overlay: NativePatchOverlayV1,
    canonical_bytes: Vec<u8>,
    patch_overlay_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePatchByteCarrierV1 {
    pub path: String,
    pub operation: PatchOperationKindV1,
    bytes: Vec<u8>,
}
impl NativePatchByteCarrierV1 {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPatchByteCarrierSet {
    entries: Vec<NativePatchByteCarrierV1>,
    canonical_bytes: Vec<u8>,
    patch_byte_carrier_set_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedNativeArchiveFileV1 {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedNativeArchiveV1 {
    pub package_id: String,
    pub base_archive_digest: String,
    pub files: Vec<CapturedNativeArchiveFileV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeResultTreeFileV1 {
    pub path: String,
    pub byte_digest: String,
    pub byte_length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeResultTreeCandidateV1 {
    files: Vec<NativeResultTreeFileV1>,
    file_bytes: BTreeMap<String, Vec<u8>>,
    canonical_bytes: Vec<u8>,
    result_tree_digest: String,
}
impl NativeResultTreeCandidateV1 {
    pub fn files(&self) -> &[NativeResultTreeFileV1] {
        &self.files
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn result_tree_digest(&self) -> &str {
        &self.result_tree_digest
    }
    pub fn file_bytes(&self, path: &str) -> Option<&[u8]> {
        self.file_bytes.get(path).map(Vec::as_slice)
    }
}
impl ValidatedPatchByteCarrierSet {
    pub fn entries(&self) -> &[NativePatchByteCarrierV1] {
        &self.entries
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn patch_byte_carrier_set_digest(&self) -> &str {
        &self.patch_byte_carrier_set_digest
    }
}
impl ValidatedPatchOverlayPlan {
    pub fn overlay(&self) -> &NativePatchOverlayV1 {
        &self.overlay
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn patch_overlay_digest(&self) -> &str {
        &self.patch_overlay_digest
    }
}

fn entries(value: &Value) -> Result<&[(String, Value)], OverlayError> {
    match value {
        Value::Map(rows) => Ok(rows),
        _ => Err(OverlayError("overlay value is not a record")),
    }
}

fn exact_keys(value: &Value, expected: &[&str]) -> Result<(), OverlayError> {
    let rows = entries(value)?;
    if rows.len() != expected.len()
        || expected
            .iter()
            .any(|key| !rows.iter().any(|(actual, _)| actual == key))
    {
        return Err(OverlayError("overlay fields are not exact"));
    }
    Ok(())
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, OverlayError> {
    value
        .field(name)
        .ok_or(OverlayError("required field missing"))
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, OverlayError> {
    field(value, name)?
        .as_text()
        .ok_or(OverlayError("required text malformed"))
}

fn digest(value: &Value) -> Result<String, OverlayError> {
    let Value::Text(text) = value else {
        return Err(OverlayError("digest is not text"));
    };
    if text.len() != 64
        || text == ZERO_SHA256
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OverlayError("digest is not nonzero lowercase SHA-256"));
    }
    Ok(text.clone())
}

fn nullable_digest(value: &Value) -> Result<Option<String>, OverlayError> {
    match value {
        Value::Null => Ok(None),
        _ => digest(value).map(Some),
    }
}

fn nullable_length(value: &Value) -> Result<Option<u64>, OverlayError> {
    match value {
        Value::Null => Ok(None),
        Value::Unsigned(length) if *length <= MAX_NEW_FILE_BYTES => Ok(Some(*length)),
        _ => Err(OverlayError("new byte length violates the file bound")),
    }
}

fn validate_new_bytes(length: u64, digest_value: &str) -> Result<(), OverlayError> {
    if (length == 0) != (digest_value == EMPTY_SHA256) {
        return Err(OverlayError("empty-file digest equation violated"));
    }
    Ok(())
}

fn capture_operation(value: &Value) -> Result<NativePatchOperationV1, OverlayError> {
    exact_keys(value, OPERATION_KEYS)?;
    let operation = match text(value, "operation")? {
        "add" => PatchOperationKindV1::Add,
        "delete" => PatchOperationKindV1::Delete,
        "replace" => PatchOperationKindV1::Replace,
        _ => return Err(OverlayError("operation tag is unknown")),
    };
    let path = text(value, "path")?;
    if path.len() > Limits::WIRE.max_text_bytes
        || !canonical_relative(path)
        || path == ".cargo-checksum.json"
    {
        return Err(OverlayError("operation path is not admitted"));
    }
    let old_byte_digest = nullable_digest(field(value, "oldByteDigest")?)?;
    let new_byte_digest = nullable_digest(field(value, "newByteDigest")?)?;
    let new_byte_length = nullable_length(field(value, "newByteLength")?)?;
    match operation {
        PatchOperationKindV1::Delete => {
            if old_byte_digest.is_none() || new_byte_digest.is_some() || new_byte_length.is_some() {
                return Err(OverlayError("delete equation violated"));
            }
        }
        PatchOperationKindV1::Add => {
            if old_byte_digest.is_some() || new_byte_digest.is_none() || new_byte_length.is_none() {
                return Err(OverlayError("add equation violated"));
            }
            validate_new_bytes(
                new_byte_length.unwrap_or_default(),
                new_byte_digest.as_deref().unwrap_or_default(),
            )?;
        }
        PatchOperationKindV1::Replace => {
            if old_byte_digest.is_none() || new_byte_digest.is_none() || new_byte_length.is_none() {
                return Err(OverlayError("replace equation violated"));
            }
            if old_byte_digest == new_byte_digest {
                return Err(OverlayError("replace is a no-op"));
            }
            validate_new_bytes(
                new_byte_length.unwrap_or_default(),
                new_byte_digest.as_deref().unwrap_or_default(),
            )?;
        }
    }
    Ok(NativePatchOperationV1 {
        operation,
        path: path.to_owned(),
        old_byte_digest,
        new_byte_digest,
        new_byte_length,
    })
}

pub fn capture_patch_overlay(bytes: &[u8]) -> Result<ValidatedPatchOverlayPlan, OverlayError> {
    let value = decode_canonical(bytes, Limits::WIRE)
        .map_err(|_| OverlayError("canonical decode refused"))?;
    exact_keys(&value, ROOT_KEYS)?;
    if text(&value, "schema")? != OVERLAY_SCHEMA
        || field(&value, "version")?.as_u64() != Some(1)
        || text(&value, "packageId")? != OVERLAY_PACKAGE_ID
    {
        return Err(OverlayError(
            "schema, version, or package identity is not frozen",
        ));
    }
    let rationale = text(&value, "rationale")?;
    if rationale.is_empty() || rationale.len() > Limits::WIRE.max_text_bytes {
        return Err(OverlayError("rationale violates the bound"));
    }
    let Value::Array(operation_values) = field(&value, "operations")? else {
        return Err(OverlayError("operations are not an array"));
    };
    if operation_values.is_empty() || operation_values.len() > MAX_OPERATIONS {
        return Err(OverlayError("operation count violates the bound"));
    }
    let operations = operation_values
        .iter()
        .map(capture_operation)
        .collect::<Result<Vec<_>, _>>()?;
    let mut prior: Option<&str> = None;
    let mut folded = BTreeSet::new();
    let mut aggregate = 0u64;
    for operation in &operations {
        if prior.is_some_and(|path| path.as_bytes() >= operation.path.as_bytes()) {
            return Err(OverlayError("operations are not strictly path-sorted"));
        }
        prior = Some(&operation.path);
        if !folded.insert(operation.path.to_ascii_lowercase()) {
            return Err(OverlayError(
                "operation paths collide under ASCII case folding",
            ));
        }
        aggregate = aggregate
            .checked_add(operation.new_byte_length.unwrap_or(0))
            .ok_or(OverlayError("aggregate new bytes overflow"))?;
        if aggregate > MAX_AGGREGATE_NEW_BYTES {
            return Err(OverlayError("aggregate new bytes exceed the bound"));
        }
    }
    let canonical_bytes = encode_bounded(&value, Limits::WIRE)
        .map_err(|_| OverlayError("canonical encode refused"))?;
    if canonical_bytes != bytes {
        return Err(OverlayError("canonical byte identity changed"));
    }
    let mut preimage = OVERLAY_DOMAIN.to_vec();
    preimage.extend_from_slice(&canonical_bytes);
    Ok(ValidatedPatchOverlayPlan {
        overlay: NativePatchOverlayV1 {
            base_archive_digest: digest(field(&value, "baseArchiveDigest")?)?,
            operations,
            rationale: rationale.to_owned(),
            result_tree_digest: digest(field(&value, "resultTreeDigest")?)?,
            audit_plan_digest: digest(field(&value, "auditPlanDigest")?)?,
        },
        canonical_bytes,
        patch_overlay_digest: sha256_hex(&preimage),
    })
}

const CARRIER_LIMITS: Limits = Limits {
    max_bytes: MAX_CARRIER_SET_ENCODED_BYTES,
    max_depth: 16,
    max_items: 65_536,
    max_collection_items: MAX_OPERATIONS,
    max_text_bytes: 4_096,
};

pub fn capture_patch_byte_carrier_set(
    bytes: &[u8],
) -> Result<ValidatedPatchByteCarrierSet, OverlayError> {
    let value = decode_canonical(bytes, CARRIER_LIMITS)
        .map_err(|_| OverlayError("canonical carrier decode refused"))?;
    exact_keys(&value, CARRIER_ROOT_KEYS)?;
    if text(&value, "schema")? != CARRIER_SET_SCHEMA
        || field(&value, "version")?.as_u64() != Some(1)
        || text(&value, "packageId")? != OVERLAY_PACKAGE_ID
    {
        return Err(OverlayError(
            "carrier schema, version, or package identity is not frozen",
        ));
    }
    let Value::Array(rows) = field(&value, "entries")? else {
        return Err(OverlayError("carrier entries are not an array"));
    };
    if rows.len() > MAX_OPERATIONS {
        return Err(OverlayError("carrier entry count exceeds the bound"));
    }
    let mut entries = Vec::with_capacity(rows.len());
    let mut prior: Option<&str> = None;
    let mut folded = BTreeSet::new();
    let mut aggregate = 0u64;
    for row in rows {
        exact_keys(row, CARRIER_ENTRY_KEYS)?;
        let operation = match text(row, "operation")? {
            "add" => PatchOperationKindV1::Add,
            "replace" => PatchOperationKindV1::Replace,
            _ => return Err(OverlayError("carrier operation is not add/replace")),
        };
        let path = text(row, "path")?;
        if path.len() > Limits::WIRE.max_text_bytes
            || !canonical_relative(path)
            || path == ".cargo-checksum.json"
        {
            return Err(OverlayError("carrier path is not admitted"));
        }
        if prior.is_some_and(|value| value.as_bytes() >= path.as_bytes()) {
            return Err(OverlayError("carrier entries are not strictly path-sorted"));
        }
        prior = Some(path);
        if !folded.insert(path.to_ascii_lowercase()) {
            return Err(OverlayError(
                "carrier paths collide under ASCII case folding",
            ));
        }
        let Value::Bytes(row_bytes) = field(row, "bytes")? else {
            return Err(OverlayError("carrier bytes are not a byte string"));
        };
        if row_bytes.len() as u64 > MAX_NEW_FILE_BYTES {
            return Err(OverlayError("carrier bytes exceed the file bound"));
        }
        aggregate = aggregate
            .checked_add(row_bytes.len() as u64)
            .ok_or(OverlayError("aggregate carrier bytes overflow"))?;
        if aggregate > MAX_AGGREGATE_NEW_BYTES {
            return Err(OverlayError("aggregate carrier bytes exceed the bound"));
        }
        entries.push(NativePatchByteCarrierV1 {
            path: path.to_owned(),
            operation,
            bytes: row_bytes.clone(),
        });
    }
    let canonical_bytes = encode_bounded(&value, CARRIER_LIMITS)
        .map_err(|_| OverlayError("canonical carrier encode refused"))?;
    if canonical_bytes != bytes {
        return Err(OverlayError("canonical carrier byte identity changed"));
    }
    let mut preimage = CARRIER_SET_DOMAIN.to_vec();
    preimage.extend_from_slice(&canonical_bytes);
    Ok(ValidatedPatchByteCarrierSet {
        entries,
        canonical_bytes,
        patch_byte_carrier_set_digest: sha256_hex(&preimage),
    })
}

pub fn join_patch_application_inputs(
    overlay: &ValidatedPatchOverlayPlan,
    carriers: &ValidatedPatchByteCarrierSet,
) -> Result<(), OverlayError> {
    let expected = overlay
        .overlay()
        .operations
        .iter()
        .filter(|operation| operation.operation != PatchOperationKindV1::Delete)
        .collect::<Vec<_>>();
    if expected.len() != carriers.entries.len() {
        return Err(OverlayError("carrier/overlay cardinality mismatch"));
    }
    for (operation, carrier) in expected.iter().zip(&carriers.entries) {
        let carrier_digest = sha256_hex(&carrier.bytes);
        if operation.path != carrier.path || operation.operation != carrier.operation {
            return Err(OverlayError("carrier/overlay path or operation mismatch"));
        }
        if operation.new_byte_length != Some(carrier.bytes.len() as u64)
            || operation.new_byte_digest.as_deref() != Some(carrier_digest.as_str())
        {
            return Err(OverlayError(
                "carrier bytes do not reproduce the overlay equation",
            ));
        }
    }
    Ok(())
}

fn capture_archive_tree(
    archive: &CapturedNativeArchiveV1,
) -> Result<BTreeMap<String, Vec<u8>>, OverlayError> {
    if archive.package_id != OVERLAY_PACKAGE_ID
        || digest(&Value::Text(archive.base_archive_digest.clone())).is_err()
        || archive.files.len() > MAX_ARCHIVE_FILES
    {
        return Err(OverlayError(
            "captured archive identity or file count is malformed",
        ));
    }
    let mut tree = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut prior: Option<&str> = None;
    let mut aggregate = 0u64;
    for row in &archive.files {
        if row.path.len() > Limits::WIRE.max_text_bytes
            || !canonical_relative(&row.path)
            || row.path == ".cargo-checksum.json"
            || row.bytes.len() as u64 > MAX_NEW_FILE_BYTES
            || prior.is_some_and(|path| path.as_bytes() >= row.path.as_bytes())
            || !folded.insert(row.path.to_ascii_lowercase())
        {
            return Err(OverlayError(
                "captured archive row, ordering, or case identity is malformed",
            ));
        }
        prior = Some(&row.path);
        aggregate = aggregate
            .checked_add(row.bytes.len() as u64)
            .ok_or(OverlayError("captured archive aggregate overflow"))?;
        if aggregate > MAX_AGGREGATE_NEW_BYTES {
            return Err(OverlayError("captured archive aggregate exceeds the bound"));
        }
        tree.insert(row.path.clone(), row.bytes.clone());
    }
    Ok(tree)
}

pub fn derive_result_tree_candidate(
    overlay: &ValidatedPatchOverlayPlan,
    carriers: &ValidatedPatchByteCarrierSet,
    archive: &CapturedNativeArchiveV1,
) -> Result<NativeResultTreeCandidateV1, OverlayError> {
    join_patch_application_inputs(overlay, carriers)?;
    if archive.base_archive_digest != overlay.overlay.base_archive_digest {
        return Err(OverlayError("overlay is bound to a different base archive"));
    }
    let mut tree = capture_archive_tree(archive)?;
    let carrier_map = carriers
        .entries
        .iter()
        .map(|row| (row.path.as_str(), row.bytes.as_slice()))
        .collect::<BTreeMap<_, _>>();
    for operation in &overlay.overlay.operations {
        if tree
            .keys()
            .any(|path| path != &operation.path && path.eq_ignore_ascii_case(&operation.path))
        {
            return Err(OverlayError("operation case-collides with a base member"));
        }
        let existing = tree.get(&operation.path);
        let carrier = carrier_map.get(operation.path.as_str()).copied();
        match operation.operation {
            PatchOperationKindV1::Add => {
                if existing.is_some() || carrier.is_none() {
                    return Err(OverlayError("add target exists or carrier is missing"));
                }
                tree.insert(operation.path.clone(), carrier.unwrap_or_default().to_vec());
            }
            PatchOperationKindV1::Delete | PatchOperationKindV1::Replace => {
                let Some(old_bytes) = existing else {
                    return Err(OverlayError("old-byte equation or target existence failed"));
                };
                if operation.old_byte_digest.as_deref() != Some(sha256_hex(old_bytes).as_str()) {
                    return Err(OverlayError("old-byte equation or target existence failed"));
                }
                if operation.operation == PatchOperationKindV1::Delete {
                    if carrier.is_some() {
                        return Err(OverlayError("delete unexpectedly has carrier bytes"));
                    }
                    tree.remove(&operation.path);
                } else {
                    let Some(new_bytes) = carrier else {
                        return Err(OverlayError("replace carrier is missing"));
                    };
                    tree.insert(operation.path.clone(), new_bytes.to_vec());
                }
            }
        }
    }
    let mut files = Vec::with_capacity(tree.len());
    let mut folded = BTreeSet::new();
    let mut aggregate = 0u64;
    for (path, bytes) in &tree {
        if !folded.insert(path.to_ascii_lowercase()) {
            return Err(OverlayError(
                "result tree collides under ASCII case folding",
            ));
        }
        aggregate = aggregate
            .checked_add(bytes.len() as u64)
            .ok_or(OverlayError("result tree aggregate overflow"))?;
        if aggregate > MAX_AGGREGATE_NEW_BYTES {
            return Err(OverlayError("result tree aggregate exceeds the bound"));
        }
        files.push(NativeResultTreeFileV1 {
            path: path.clone(),
            byte_digest: sha256_hex(bytes),
            byte_length: bytes.len() as u64,
        });
    }
    let value = Value::Map(vec![
        ("schema".into(), Value::Text(RESULT_TREE_SCHEMA.into())),
        ("version".into(), Value::Unsigned(1)),
        ("packageId".into(), Value::Text(OVERLAY_PACKAGE_ID.into())),
        (
            "files".into(),
            Value::Array(
                files
                    .iter()
                    .map(|row| {
                        Value::Map(vec![
                            ("path".into(), Value::Text(row.path.clone())),
                            ("byteDigest".into(), Value::Text(row.byte_digest.clone())),
                            ("byteLength".into(), Value::Unsigned(row.byte_length)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);
    let canonical_bytes = encode_bounded(&value, Limits::WIRE)
        .map_err(|_| OverlayError("result tree canonical encode refused"))?;
    let mut preimage = RESULT_TREE_DOMAIN.to_vec();
    preimage.extend_from_slice(&canonical_bytes);
    Ok(NativeResultTreeCandidateV1 {
        files,
        file_bytes: tree,
        canonical_bytes,
        result_tree_digest: sha256_hex(&preimage),
    })
}

pub fn validate_result_tree_application(
    overlay: &ValidatedPatchOverlayPlan,
    carriers: &ValidatedPatchByteCarrierSet,
    archive: &CapturedNativeArchiveV1,
) -> Result<NativeResultTreeCandidateV1, OverlayError> {
    let result = derive_result_tree_candidate(overlay, carriers, archive)?;
    if result.result_tree_digest != overlay.overlay.result_tree_digest {
        return Err(OverlayError(
            "derived result tree does not match overlay commitment",
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        Value::Map(vec![
            ("schema".into(), Value::Text(OVERLAY_SCHEMA.into())),
            ("version".into(), Value::Unsigned(1)),
            ("packageId".into(), Value::Text(OVERLAY_PACKAGE_ID.into())),
            (
                "rationale".into(),
                Value::Text("remove build script".into()),
            ),
            (
                "operations".into(),
                Value::Array(vec![Value::Map(vec![
                    ("path".into(), Value::Text("build.rs".into())),
                    ("operation".into(), Value::Text("delete".into())),
                    ("newByteDigest".into(), Value::Null),
                    ("newByteLength".into(), Value::Null),
                    ("oldByteDigest".into(), Value::Text("1".repeat(64))),
                ])]),
            ),
            ("auditPlanDigest".into(), Value::Text("2".repeat(64))),
            ("resultTreeDigest".into(), Value::Text("3".repeat(64))),
            ("baseArchiveDigest".into(), Value::Text("4".repeat(64))),
        ])
    }

    #[test]
    fn accepts_canonical_overlay_and_domain_separates_identity() {
        let bytes = encode_bounded(&fixture(), Limits::WIRE).expect("fixture encodes");
        let captured = capture_patch_overlay(&bytes).expect("fixture captures");
        assert_eq!(captured.canonical_bytes(), bytes);
        assert_eq!(captured.overlay().operations.len(), 1);
        assert_eq!(captured.patch_overlay_digest().len(), 64);
        assert_ne!(captured.patch_overlay_digest(), sha256_hex(&bytes));
    }

    #[test]
    fn refuses_reserved_path_and_operation_equation_mutants() {
        let mut reserved = fixture();
        if let Value::Array(rows) = field(&reserved, "operations").expect("operations").clone() {
            let mut row = rows[0].clone();
            if let Value::Map(entries) = &mut row {
                entries
                    .iter_mut()
                    .find(|(key, _)| key == "path")
                    .expect("path")
                    .1 = Value::Text(".cargo-checksum.json".into());
            }
            if let Value::Map(root) = &mut reserved {
                root.iter_mut()
                    .find(|(key, _)| key == "operations")
                    .expect("operations")
                    .1 = Value::Array(vec![row]);
            }
        }
        let bytes = encode_bounded(&reserved, Limits::WIRE).expect("mutant encodes");
        assert!(capture_patch_overlay(&bytes).is_err());

        let mut equation = fixture();
        if let Value::Map(root) = &mut equation {
            let Value::Array(rows) = &mut root
                .iter_mut()
                .find(|(key, _)| key == "operations")
                .expect("operations")
                .1
            else {
                panic!("array")
            };
            let Value::Map(entries) = &mut rows[0] else {
                panic!("map")
            };
            entries
                .iter_mut()
                .find(|(key, _)| key == "newByteLength")
                .expect("length")
                .1 = Value::Unsigned(1);
        }
        let bytes = encode_bounded(&equation, Limits::WIRE).expect("mutant encodes");
        assert!(capture_patch_overlay(&bytes).is_err());
    }

    fn carrier_fixture(bytes: &[u8]) -> Value {
        Value::Map(vec![
            ("schema".into(), Value::Text(CARRIER_SET_SCHEMA.into())),
            ("version".into(), Value::Unsigned(1)),
            ("packageId".into(), Value::Text(OVERLAY_PACKAGE_ID.into())),
            (
                "entries".into(),
                Value::Array(vec![Value::Map(vec![
                    ("path".into(), Value::Text("Cargo.toml".into())),
                    ("operation".into(), Value::Text("replace".into())),
                    ("bytes".into(), Value::Bytes(bytes.to_vec())),
                ])]),
            ),
        ])
    }

    fn replace_overlay(bytes: &[u8]) -> Value {
        Value::Map(vec![
            ("schema".into(), Value::Text(OVERLAY_SCHEMA.into())),
            ("version".into(), Value::Unsigned(1)),
            ("packageId".into(), Value::Text(OVERLAY_PACKAGE_ID.into())),
            (
                "rationale".into(),
                Value::Text("remove build script".into()),
            ),
            (
                "operations".into(),
                Value::Array(vec![Value::Map(vec![
                    ("path".into(), Value::Text("Cargo.toml".into())),
                    ("operation".into(), Value::Text("replace".into())),
                    ("newByteDigest".into(), Value::Text(sha256_hex(bytes))),
                    ("newByteLength".into(), Value::Unsigned(bytes.len() as u64)),
                    ("oldByteDigest".into(), Value::Text("1".repeat(64))),
                ])]),
            ),
            ("auditPlanDigest".into(), Value::Text("2".repeat(64))),
            ("resultTreeDigest".into(), Value::Text("3".repeat(64))),
            ("baseArchiveDigest".into(), Value::Text("4".repeat(64))),
        ])
    }

    #[test]
    fn carrier_capture_and_overlay_join_are_exact_and_domain_separated() {
        let payload = b"new Cargo manifest\n";
        let carrier_bytes =
            encode_bounded(&carrier_fixture(payload), CARRIER_LIMITS).expect("carrier encodes");
        let overlay_bytes =
            encode_bounded(&replace_overlay(payload), Limits::WIRE).expect("overlay encodes");
        let carrier = capture_patch_byte_carrier_set(&carrier_bytes).expect("carrier captures");
        let overlay = capture_patch_overlay(&overlay_bytes).expect("overlay captures");
        assert_eq!(carrier.canonical_bytes(), carrier_bytes);
        assert_eq!(carrier.entries()[0].bytes(), payload);
        assert_ne!(
            carrier.patch_byte_carrier_set_digest(),
            sha256_hex(&carrier_bytes)
        );
        join_patch_application_inputs(&overlay, &carrier).expect("inputs join");

        let bad_bytes = encode_bounded(&carrier_fixture(b"different\n"), CARRIER_LIMITS)
            .expect("mutant encodes");
        let bad = capture_patch_byte_carrier_set(&bad_bytes).expect("mutant captures structurally");
        assert!(join_patch_application_inputs(&overlay, &bad).is_err());

        let oversized = encode_bounded(
            &carrier_fixture(&vec![0; MAX_NEW_FILE_BYTES as usize + 1]),
            CARRIER_LIMITS,
        )
        .expect("oversized semantic mutant still fits the carrier envelope");
        assert!(capture_patch_byte_carrier_set(&oversized).is_err());
    }

    #[test]
    fn pure_application_matches_the_typescript_golden_and_refuses_mutants() {
        let old_manifest = b"old manifest\n";
        let new_manifest = b"new manifest\n";
        let build_script = b"fn main() {}\n";
        let library = b"pub fn keep() {}\n";
        let mut overlay_value = replace_overlay(new_manifest);
        let Value::Map(root) = &mut overlay_value else {
            panic!("root map")
        };
        root.iter_mut()
            .find(|(key, _)| key == "baseArchiveDigest")
            .unwrap()
            .1 = Value::Text(format!("{:064x}", 1));
        root.iter_mut()
            .find(|(key, _)| key == "resultTreeDigest")
            .unwrap()
            .1 =
            Value::Text("4e960da8bb98e1f597df4bf41c80ca12c8a6fb949ece7fd22baea1fb0846b000".into());
        let Value::Array(operations) = &mut root
            .iter_mut()
            .find(|(key, _)| key == "operations")
            .unwrap()
            .1
        else {
            panic!("operations")
        };
        let Value::Map(replace) = &mut operations[0] else {
            panic!("replace")
        };
        replace
            .iter_mut()
            .find(|(key, _)| key == "oldByteDigest")
            .unwrap()
            .1 = Value::Text(sha256_hex(old_manifest));
        operations.push(Value::Map(vec![
            ("path".into(), Value::Text("build.rs".into())),
            ("operation".into(), Value::Text("delete".into())),
            ("newByteDigest".into(), Value::Null),
            ("newByteLength".into(), Value::Null),
            (
                "oldByteDigest".into(),
                Value::Text(sha256_hex(build_script)),
            ),
        ]));
        let overlay =
            capture_patch_overlay(&encode_bounded(&overlay_value, Limits::WIRE).unwrap()).unwrap();
        let carriers = capture_patch_byte_carrier_set(
            &encode_bounded(&carrier_fixture(new_manifest), CARRIER_LIMITS).unwrap(),
        )
        .unwrap();
        let archive = CapturedNativeArchiveV1 {
            package_id: OVERLAY_PACKAGE_ID.into(),
            base_archive_digest: format!("{:064x}", 1),
            files: vec![
                CapturedNativeArchiveFileV1 {
                    path: "Cargo.toml".into(),
                    bytes: old_manifest.to_vec(),
                },
                CapturedNativeArchiveFileV1 {
                    path: "build.rs".into(),
                    bytes: build_script.to_vec(),
                },
                CapturedNativeArchiveFileV1 {
                    path: "src/lib.rs".into(),
                    bytes: library.to_vec(),
                },
            ],
        };
        let result = validate_result_tree_application(&overlay, &carriers, &archive).unwrap();
        assert_eq!(
            result.result_tree_digest(),
            "4e960da8bb98e1f597df4bf41c80ca12c8a6fb949ece7fd22baea1fb0846b000"
        );
        assert_eq!(
            result
                .files()
                .iter()
                .map(|row| row.path.as_str())
                .collect::<Vec<_>>(),
            vec!["Cargo.toml", "src/lib.rs"]
        );
        assert_eq!(
            result.file_bytes("Cargo.toml"),
            Some(new_manifest.as_slice())
        );
        assert!(result.file_bytes("build.rs").is_none());

        let mut wrong_base = archive.clone();
        wrong_base.base_archive_digest = format!("{:064x}", 9);
        assert!(derive_result_tree_candidate(&overlay, &carriers, &wrong_base).is_err());
        let mut collision = archive.clone();
        collision.files[2].path = "cargo.TOML".into();
        assert!(derive_result_tree_candidate(&overlay, &carriers, &collision).is_err());
    }
}
