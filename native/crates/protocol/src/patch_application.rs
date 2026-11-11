#![forbid(unsafe_code)]

//! Pure application of captured rows, with retained unverified review identities.
use crate::audit_plan::capture_audit_plan_v1;
use crate::p2_d2::{
    CapturedNativeArchiveFileV1, CapturedNativeArchiveV1, NativeResultTreeCandidateV1,
    ValidatedPatchByteCarrierSet, ValidatedPatchOverlayPlan, bind_patch_descriptor,
    validate_result_tree_application,
};
use crate::patch_capture::{CaptureError, CapturedSourceRows, byte_digest};
use crate::{Limits, Value, decode_canonical, encode_bounded, sha256_hex};

pub struct ApplicationEvidence {
    pub result: NativeResultTreeCandidateV1,
    pub canonical: Vec<u8>,
    pub checksum: Vec<u8>,
}

pub fn capture_review_inputs(bytes: &[u8]) -> Result<(), CaptureError> {
    let value = decode_canonical(bytes, Limits::WIRE).map_err(|_| CaptureError::Malformed)?;
    let Value::Map(rows) = &value else {
        return Err(CaptureError::Malformed);
    };
    let keys = [
        "schema",
        "version",
        "toolchain",
        "unsafeCode",
        "license",
        "advisory",
        "reproducibility",
        "provenance",
    ];
    if bytes.len() > 65_536
        || rows.len() != keys.len()
        || keys.iter().any(|key| value.field(key).is_none())
        || value.field("schema") != Some(&Value::Text("keep.p2-d2-review-inputs".into()))
        || value.field("version") != Some(&Value::Unsigned(1))
    {
        return Err(CaptureError::Malformed);
    }
    for key in &keys[2..] {
        match value.field(key) {
            Some(Value::Null) => (),
            Some(Value::Text(s))
                if s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && s.bytes().any(|b| b != b'0') =>
            {
                ()
            }
            _ => return Err(CaptureError::Malformed),
        }
    }
    Ok(())
}

pub fn apply_snapshot(
    source: &CapturedSourceRows,
    overlay: &ValidatedPatchOverlayPlan,
    carriers: &ValidatedPatchByteCarrierSet,
    audit: &[u8],
    review: &[u8],
    request_digest: &str,
) -> Result<ApplicationEvidence, CaptureError> {
    let audit = capture_audit_plan_v1(audit).map_err(|_| CaptureError::Malformed)?;
    if audit.audit_plan_digest() != overlay.overlay().audit_plan_digest {
        return Err(CaptureError::Integrity);
    }
    capture_review_inputs(review)?;
    let descriptor =
        bind_patch_descriptor(overlay, carriers, &overlay.overlay().base_archive_digest)
            .map_err(|_| CaptureError::Integrity)?;
    let archive = CapturedNativeArchiveV1 {
        package_id: "curve25519-dalek@5.0.0".into(),
        base_archive_digest: overlay.overlay().base_archive_digest.clone(),
        files: source
            .files()
            .iter()
            .map(|f| CapturedNativeArchiveFileV1 {
                path: f.path().into(),
                bytes: f.bytes().to_vec(),
            })
            .collect(),
    };
    let result = validate_result_tree_application(overlay, carriers, &archive)
        .map_err(|_| CaptureError::Integrity)?;
    let paths: std::collections::BTreeSet<_> = result
        .files()
        .iter()
        .map(|f| f.path.to_ascii_lowercase())
        .collect();
    for path in &paths {
        let parts: Vec<_> = path.split('/').collect();
        if path == ".cargo-checksum.json"
            || path.starts_with(".cargo-checksum.json/")
            || (1..parts.len()).any(|n| paths.contains(&parts[..n].join("/")))
        {
            return Err(CaptureError::Path);
        }
    }
    let files = result
        .files()
        .iter()
        .map(|f| format!("\"{}\":\"{}\"", f.path, f.byte_digest))
        .collect::<Vec<_>>()
        .join(",");
    let checksum = format!("{{\"files\":{{{files}}},\"package\":null}}\n").into_bytes();
    let mut checksum_preimage = b"keep.p2-d2-cargo-checksum-artifact/v1\0".to_vec();
    checksum_preimage.extend_from_slice(&checksum);
    let text = |s: &str| Value::Text(s.into());
    let canonical = encode_bounded(
        &Value::Map(vec![
            ("schema".into(), text("keep.p2-d2-patch-application")),
            ("version".into(), Value::Unsigned(1)),
            ("packageId".into(), text("curve25519-dalek@5.0.0")),
            ("requestDigest".into(), text(request_digest)),
            ("sourceRowDigest".into(), text(source.row_digest())),
            (
                "baseArchiveDigest".into(),
                text(&archive.base_archive_digest),
            ),
            (
                "patchDescriptorDigest".into(),
                text(descriptor.descriptor_digest()),
            ),
            ("resultTreeDigest".into(), text(result.result_tree_digest())),
            ("auditPlanDigest".into(), text(audit.audit_plan_digest())),
            ("reviewInputsDigest".into(), text(&byte_digest(review))),
            (
                "cargoChecksumArtifactDigest".into(),
                text(&sha256_hex(&checksum_preimage)),
            ),
            ("reviewStatus".into(), text("unverified")),
            ("admission".into(), Value::Bool(false)),
            ("launch".into(), Value::Bool(false)),
        ]),
        Limits::WIRE,
    )
    .map_err(|_| CaptureError::Limit)?;
    Ok(ApplicationEvidence {
        result,
        canonical,
        checksum,
    })
}
