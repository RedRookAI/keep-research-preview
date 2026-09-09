#![forbid(unsafe_code)]

//! Pure AuditPlanV1 capture. This module has no I/O, signing, review, or authority capability.

use keep_native_protocol::{Limits, Value, decode_canonical, encode_bounded, sha256_hex};
use std::collections::BTreeSet;

const DOMAIN: &[u8] = b"keep.p2-d2-audit-plan/v1\0";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ROLES: &[&str] = &[
    "advisory",
    "build-policy",
    "correctness",
    "license",
    "unsafe-contract",
];
const PLAN_KEYS: &[&str] = &[
    "schema",
    "version",
    "planId",
    "claimSchema",
    "reviewerRegistry",
    "producerKeyDigests",
    "validatorKeyDigests",
    "requiredClaims",
    "separationPolicy",
];
const REGISTRY_KEYS: &[&str] = &[
    "schema",
    "version",
    "registryId",
    "revocationListDigest",
    "reviewers",
];
const REVIEWER_KEYS: &[&str] = &[
    "principal",
    "reviewerFamily",
    "custodianFamily",
    "mechanism",
    "publicKeyAlgorithm",
    "publicKeyOrTrustRoot",
    "issuer",
    "subject",
    "repository",
    "workflow",
    "allowedRoles",
    "validFromCounter",
    "validThroughCounter",
    "revocationIdentity",
];
const CLAIM_KEYS: &[&str] = &[
    "role",
    "minimumReviewers",
    "minimumReviewerFamilies",
    "minimumCustodianFamilies",
];
const SEPARATION_KEYS: &[&str] = &[
    "distinctPrincipals",
    "distinctReviewerFamilies",
    "distinctCustodianFamilies",
    "producerReviewerDisjoint",
    "validatorReviewerDisjoint",
    "keysOffCollectorHost",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditPlanError(pub &'static str);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAuditPlanV1 {
    canonical_bytes: Vec<u8>,
    audit_plan_digest: String,
}
impl ValidatedAuditPlanV1 {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn audit_plan_digest(&self) -> &str {
        &self.audit_plan_digest
    }
}

fn record(value: &Value) -> Result<&[(String, Value)], AuditPlanError> {
    if let Value::Map(rows) = value {
        Ok(rows)
    } else {
        Err(AuditPlanError("value is not a record"))
    }
}
fn exact(value: &Value, expected: &[&str]) -> Result<(), AuditPlanError> {
    let rows = record(value)?;
    if rows.len() != expected.len()
        || expected
            .iter()
            .any(|key| !rows.iter().any(|(actual, _)| actual == key))
    {
        Err(AuditPlanError("record fields are not exact"))
    } else {
        Ok(())
    }
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, AuditPlanError> {
    value
        .field(name)
        .ok_or(AuditPlanError("required field is absent"))
}
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, AuditPlanError> {
    field(value, name)?
        .as_text()
        .ok_or(AuditPlanError("required text is malformed"))
}
fn identifier(value: &Value) -> Result<&str, AuditPlanError> {
    let Value::Text(text) = value else {
        return Err(AuditPlanError("identifier is not text"));
    };
    if text.is_empty()
        || text.len() > 256
        || !text.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
        || !text
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !text
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        Err(AuditPlanError("identifier grammar refused"))
    } else {
        Ok(text)
    }
}
fn digest(value: &Value) -> Result<&str, AuditPlanError> {
    let Value::Text(text) = value else {
        return Err(AuditPlanError("digest is not text"));
    };
    if text.len() != 64
        || text == ZERO
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Err(AuditPlanError("digest is not nonzero lowercase SHA-256"))
    } else {
        Ok(text)
    }
}
fn nullable_native_text(value: &Value) -> Result<Option<&str>, AuditPlanError> {
    match value {
        Value::Null => Ok(None),
        Value::Text(text)
            if !text.is_empty()
                && text.len() <= 512
                && text.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) =>
        {
            Ok(Some(text))
        }
        _ => Err(AuditPlanError("nullable identity text is malformed")),
    }
}
fn ordered_digests(value: &Value) -> Result<Vec<&str>, AuditPlanError> {
    let Value::Array(rows) = value else {
        return Err(AuditPlanError("digest set is not an array"));
    };
    if rows.is_empty() {
        return Err(AuditPlanError("digest set is empty"));
    }
    let values = rows.iter().map(digest).collect::<Result<Vec<_>, _>>()?;
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(AuditPlanError("digest set is not strictly ordered"));
    }
    Ok(values)
}
fn exact_roles(value: &Value) -> Result<(), AuditPlanError> {
    let Value::Array(rows) = value else {
        return Err(AuditPlanError("roles are not an array"));
    };
    if rows.len() != ROLES.len()
        || rows
            .iter()
            .zip(ROLES)
            .any(|(row, expected)| row.as_text() != Some(expected))
    {
        Err(AuditPlanError("role set differs from frozen roles"))
    } else {
        Ok(())
    }
}

pub fn capture_audit_plan_v1(bytes: &[u8]) -> Result<ValidatedAuditPlanV1, AuditPlanError> {
    if bytes.is_empty() || bytes.len() > Limits::WIRE.max_bytes {
        return Err(AuditPlanError("encoded bound refused"));
    }
    let value = decode_canonical(bytes, Limits::WIRE)
        .map_err(|_| AuditPlanError("canonical decode refused"))?;
    if encode_bounded(&value, Limits::WIRE)
        .map_err(|_| AuditPlanError("canonical re-encode refused"))?
        != bytes
    {
        return Err(AuditPlanError("canonical bytes disagreed"));
    }
    exact(&value, PLAN_KEYS)?;
    if text(&value, "schema")? != "keep.p2-d2-audit-plan"
        || field(&value, "version")? != &Value::Unsigned(1)
        || text(&value, "claimSchema")? != "keep.p2-d2-evidence/v1"
    {
        return Err(AuditPlanError("plan identity disagreed"));
    }
    identifier(field(&value, "planId")?)?;
    let producers = ordered_digests(field(&value, "producerKeyDigests")?)?;
    let validators = ordered_digests(field(&value, "validatorKeyDigests")?)?;
    if producers.iter().any(|entry| validators.contains(entry)) {
        return Err(AuditPlanError("producer/validator overlap"));
    }

    let registry = field(&value, "reviewerRegistry")?;
    exact(registry, REGISTRY_KEYS)?;
    if text(registry, "schema")? != "keep.p2-d2-native-reviewer-registry"
        || field(registry, "version")? != &Value::Unsigned(1)
    {
        return Err(AuditPlanError("registry identity disagreed"));
    }
    identifier(field(registry, "registryId")?)?;
    digest(field(registry, "revocationListDigest")?)?;
    let Value::Array(reviewers) = field(registry, "reviewers")? else {
        return Err(AuditPlanError("reviewers are not an array"));
    };
    if !(2..=16).contains(&reviewers.len()) {
        return Err(AuditPlanError("reviewer count refused"));
    }
    let mut previous = "";
    let mut families = BTreeSet::new();
    let mut custodians = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut revocations = BTreeSet::new();
    for reviewer in reviewers {
        exact(reviewer, REVIEWER_KEYS)?;
        let principal = identifier(field(reviewer, "principal")?)?;
        if principal <= previous {
            return Err(AuditPlanError("reviewers are not principal-ordered"));
        }
        previous = principal;
        families.insert(identifier(field(reviewer, "reviewerFamily")?)?);
        custodians.insert(identifier(field(reviewer, "custodianFamily")?)?);
        let key = digest(field(reviewer, "publicKeyOrTrustRoot")?)?;
        let revocation = digest(field(reviewer, "revocationIdentity")?)?;
        if !keys.insert(key)
            || !revocations.insert(revocation)
            || producers.contains(&key)
            || validators.contains(&key)
        {
            return Err(AuditPlanError(
                "reviewer identity duplicates or overlaps authority",
            ));
        }
        exact_roles(field(reviewer, "allowedRoles")?)?;
        let (Value::Unsigned(from), Value::Unsigned(through)) = (
            field(reviewer, "validFromCounter")?,
            field(reviewer, "validThroughCounter")?,
        ) else {
            return Err(AuditPlanError("validity counter malformed"));
        };
        if from > through {
            return Err(AuditPlanError("validity interval inverted"));
        }
        let mechanism = text(reviewer, "mechanism")?;
        let algorithm = text(reviewer, "publicKeyAlgorithm")?;
        let identities = ["issuer", "subject", "repository", "workflow"]
            .map(|name| field(reviewer, name).and_then(nullable_native_text))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        match mechanism {
            "ed25519-service"
                if algorithm == "ed25519" && identities.iter().all(Option::is_none) => {}
            "sigstore-keyless"
                if algorithm == "sigstore-fulcio-ecdsa-p256"
                    && identities.iter().all(Option::is_some) => {}
            _ => return Err(AuditPlanError("mechanism fields disagree")),
        }
    }
    if families.len() < 2 || custodians.len() < 2 {
        return Err(AuditPlanError("registry independence threshold failed"));
    }
    let Value::Array(claims) = field(&value, "requiredClaims")? else {
        return Err(AuditPlanError("claims are not an array"));
    };
    if claims.len() != ROLES.len() {
        return Err(AuditPlanError("claim set incomplete"));
    }
    for (claim, role) in claims.iter().zip(ROLES) {
        exact(claim, CLAIM_KEYS)?;
        if text(claim, "role")? != *role
            || field(claim, "minimumReviewers")? != &Value::Unsigned(2)
            || field(claim, "minimumReviewerFamilies")? != &Value::Unsigned(2)
            || field(claim, "minimumCustodianFamilies")? != &Value::Unsigned(2)
        {
            return Err(AuditPlanError("claim threshold disagreed"));
        }
    }
    let separation = field(&value, "separationPolicy")?;
    exact(separation, SEPARATION_KEYS)?;
    if SEPARATION_KEYS
        .iter()
        .any(|name| field(separation, name) != Ok(&Value::Bool(true)))
    {
        return Err(AuditPlanError("separation invariant disabled"));
    }
    let mut preimage = DOMAIN.to_vec();
    preimage.extend_from_slice(bytes);
    Ok(ValidatedAuditPlanV1 {
        canonical_bytes: bytes.to_vec(),
        audit_plan_digest: sha256_hex(&preimage),
    })
}
