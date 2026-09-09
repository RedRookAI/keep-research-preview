#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::fmt::{Display, Formatter};

mod gzip;
pub mod p2_d2;
pub mod p2_schema;
pub mod patch_capture;

pub const PROTOCOL_NAME: &str = "keep.native-boundary";
pub const PROTOCOL_VERSION: u64 = 2;

const DEPLOYMENT_PAYLOAD_KEYS: &[&str] = &[
    "schema",
    "version",
    "trustClass",
    "deploymentId",
    "deploymentEpoch",
    "deploymentBaseDigest",
    "predecessorDigest",
    "bootPolicy",
    "protocol",
    "artifacts",
    "roles",
    "channels",
    "probers",
    "provisioners",
    "b3",
    "release",
    "revocation",
    "rollback",
    "evidence",
];
const DEPLOYMENT_B3_KEYS: &[&str] = &[
    "authorityId",
    "genesisBaseDigest",
    "b3ProfileEnvelopeDigest",
    "keyEpoch",
    "assurance",
    "channelId",
];
const DEPLOYMENT_REVOCATION_KEYS: &[&str] = &[
    "authorityId",
    "keyEpoch",
    "namespace",
    "scope",
    "genesisCheckpointEnvelopeDigest",
    "minimumSequence",
    "maxStalenessCounters",
    "compromiseSemantics",
];
const DEPLOYMENT_ROLLBACK_KEYS: &[&str] = &[
    "deploymentEpoch",
    "minimumArtifactVersion",
    "predecessorDigest",
    "authorizedRollbackEnvelopeDigest",
];
const NATIVE_CLOSURE_PAYLOAD_KEYS: &[&str] = &[
    "schema",
    "version",
    "trustClass",
    "a4ReleaseBaseDigest",
    "a4ArtifactInventoryDigest",
    "nativeArtifactInventoryDigest",
    "nativeDeploymentPayloadDigest",
    "nativeDeploymentEnvelopeDigest",
    "nativePackagePayloadDigest",
    "nativeClosureBaseDigest",
    "helperArtifactDigest",
    "trampolineArtifactDigest",
    "proberArtifactDigest",
    "provisionerArtifactDigests",
    "protocolDigest",
    "evidenceSchemaDigest",
    "targetTriple",
    "variant",
    "artifactVersion",
    "buildId",
    "releaseKeyEpoch",
    "timestampKeyEpoch",
    "timestampRecordEnvelopeDigest",
    "sbomEnvelopeDigest",
    "provenanceEnvelopeDigests",
    "reproducibilityRecordEnvelopeDigest",
    "toolchainClosureEnvelopeDigest",
    "releaseTimeRevocationCheckpointEnvelopeDigest",
    "releaseTimeRevocationSequence",
    "deploymentEpoch",
    "minimumArtifactVersion",
    "predecessorDigest",
    "authorizedRollbackEnvelopeDigest",
    "b0RootEnvelopeDigest",
    "b3ProfileEnvelopeDigest",
];
const NATIVE_INDEX_PAYLOAD_KEYS: &[&str] = &[
    "schema",
    "version",
    "a4ReleaseBaseDigest",
    "deploymentEnvelopeDigest",
    "nativeClosureEnvelopeDigest",
    "b0RootEnvelopeDigest",
    "releaseKeyEpoch",
    "trustClass",
];
const EVIDENCE_KEYS: &[&str] = &[
    "schema",
    "version",
    "deploymentId",
    "deploymentEpoch",
    "bootId",
    "kernelBootId",
    "manifestDigest",
    "nativeClosureEnvelopeDigest",
    "helperArtifactDigest",
    "helperBuildId",
    "helperIncarnation",
    "protocolDigest",
    "requestId",
    "requestDigest",
    "requestNonce",
    "requestSequence",
    "challengeNonce",
    "b3ProfileEnvelopeDigest",
    "b3LeaseReceiptEnvelopeDigest",
    "b3Counter",
    "capturedCounter",
    "expiresCounter",
    "proberId",
    "proberPrincipal",
    "proberArtifactDigest",
    "proberIncarnation",
    "proberKeyEpoch",
    "revocationEnvelopeDigest",
    "roles",
    "measurements",
    "negativeProbes",
    "inheritedFdInventory",
    "cleanup",
    "previousEvidenceDigest",
    "signature",
];

const DEPLOYMENT_BASE_INPUTS: &[&str] = &[
    "deployment.payload.predecessorDigest",
    "deployment.payload.artifacts[].digest",
    "deployment.payload.roles[].artifactDigest",
    "deployment.payload.roles[].cgroup.ioMaxDigest",
    "deployment.payload.roles[].launchSeccompDigest",
    "deployment.payload.roles[].steadySeccompDigest",
    "deployment.payload.roles[].landlockDigest",
    "deployment.payload.b3.genesisBaseDigest",
    "deployment.payload.b3.b3ProfileEnvelopeDigest",
    "deployment.payload.revocation.genesisCheckpointEnvelopeDigest",
    "deployment.payload.rollback.predecessorDigest",
];
const CLOSURE_BASE_INPUTS: &[&str] = &[
    "closure.payload.a4ReleaseBaseDigest",
    "closure.payload.a4ArtifactInventoryDigest",
    "closure.payload.nativeArtifactInventoryDigest",
    "closure.payload.nativeDeploymentPayloadDigest",
    "closure.payload.nativeDeploymentEnvelopeDigest",
    "closure.payload.nativePackagePayloadDigest",
    "closure.payload.helperArtifactDigest",
    "closure.payload.trampolineArtifactDigest",
    "closure.payload.proberArtifactDigest",
    "closure.payload.provisionerArtifactDigests[]",
    "closure.payload.protocolDigest",
    "closure.payload.evidenceSchemaDigest",
    "closure.payload.sbomEnvelopeDigest",
    "closure.payload.provenanceEnvelopeDigests[]",
    "closure.payload.reproducibilityRecordEnvelopeDigest",
    "closure.payload.toolchainClosureEnvelopeDigest",
    "closure.payload.releaseTimeRevocationCheckpointEnvelopeDigest",
    "closure.payload.predecessorDigest",
    "closure.payload.authorizedRollbackEnvelopeDigest",
    "closure.payload.b0RootEnvelopeDigest",
    "closure.payload.b3ProfileEnvelopeDigest",
];
const DEPLOYMENT_PAYLOAD_INPUTS: &[&str] = &[
    "deployment.payload.predecessorDigest",
    "deployment.payload.artifacts[].digest",
    "deployment.payload.roles[].artifactDigest",
    "deployment.payload.roles[].cgroup.ioMaxDigest",
    "deployment.payload.roles[].launchSeccompDigest",
    "deployment.payload.roles[].steadySeccompDigest",
    "deployment.payload.roles[].landlockDigest",
    "deployment.payload.b3.genesisBaseDigest",
    "deployment.payload.b3.b3ProfileEnvelopeDigest",
    "deployment.payload.revocation.genesisCheckpointEnvelopeDigest",
    "deployment.payload.rollback.predecessorDigest",
    "deployment.payload.deploymentBaseDigest",
    "deployment.payload.rollback.authorizedRollbackEnvelopeDigest",
];
const CLOSURE_PAYLOAD_INPUTS: &[&str] = &[
    "closure.payload.a4ReleaseBaseDigest",
    "closure.payload.a4ArtifactInventoryDigest",
    "closure.payload.nativeArtifactInventoryDigest",
    "closure.payload.nativeDeploymentPayloadDigest",
    "closure.payload.nativeDeploymentEnvelopeDigest",
    "closure.payload.nativePackagePayloadDigest",
    "closure.payload.helperArtifactDigest",
    "closure.payload.trampolineArtifactDigest",
    "closure.payload.proberArtifactDigest",
    "closure.payload.provisionerArtifactDigests[]",
    "closure.payload.protocolDigest",
    "closure.payload.evidenceSchemaDigest",
    "closure.payload.sbomEnvelopeDigest",
    "closure.payload.provenanceEnvelopeDigests[]",
    "closure.payload.reproducibilityRecordEnvelopeDigest",
    "closure.payload.toolchainClosureEnvelopeDigest",
    "closure.payload.releaseTimeRevocationCheckpointEnvelopeDigest",
    "closure.payload.predecessorDigest",
    "closure.payload.authorizedRollbackEnvelopeDigest",
    "closure.payload.b0RootEnvelopeDigest",
    "closure.payload.b3ProfileEnvelopeDigest",
    "closure.payload.nativeClosureBaseDigest",
    "closure.payload.timestampRecordEnvelopeDigest",
];
const INDEX_PAYLOAD_INPUTS: &[&str] = &[
    "index.payload.a4ReleaseBaseDigest",
    "index.payload.deploymentEnvelopeDigest",
    "index.payload.nativeClosureEnvelopeDigest",
    "index.payload.b0RootEnvelopeDigest",
];
const OTHER_DIGEST_PATHS: &[&str] = &[
    "request.manifestDigest",
    "request.roles[].artifactDigest",
    "response.requestDigest",
    "response.helperArtifactDigest",
    "response.roleHandles[].incarnationDigest",
    "response.roleHandles[].artifactDigest",
    "response.measurements[].transcriptDigest",
    "response.evidenceBundleDigest",
    "deployment.payloadDigest",
    "closure.payloadDigest",
    "index.payloadDigest",
    "index.payload.a4ReleaseBaseDigest",
    "index.payload.deploymentEnvelopeDigest",
    "index.payload.nativeClosureEnvelopeDigest",
    "index.payload.b0RootEnvelopeDigest",
    "revocation.payloadDigest",
    "revocation.payload.previousEnvelopeDigest",
    "evidence.manifestDigest",
    "evidence.nativeClosureEnvelopeDigest",
    "evidence.helperArtifactDigest",
    "evidence.helperIncarnation",
    "evidence.protocolDigest",
    "evidence.requestDigest",
    "evidence.b3ProfileEnvelopeDigest",
    "evidence.b3LeaseReceiptEnvelopeDigest",
    "evidence.proberArtifactDigest",
    "evidence.proberIncarnation",
    "evidence.revocationEnvelopeDigest",
    "evidence.roles[].artifactDigest",
    "evidence.roles[].incarnationDigest",
    "evidence.measurements[].value.ioMaxDigest",
    "evidence.measurements[].value.filterDigest",
    "evidence.measurements[].value.rulesetDigest",
    "evidence.measurements[].value.entries[].sourceDigest",
    "evidence.measurements[].value.entries[].flagsDigest",
    "evidence.measurements[].value.pidfdDigest",
    "evidence.measurements[].value.value",
    "evidence.measurements[].value.values[]",
    "evidence.measurements[].transcriptDigest",
    "evidence.negativeProbes[].controlDigest",
    "evidence.inheritedFdInventory[].flagsDigest",
    "evidence.cleanup.journalDigest",
    "evidence.previousEvidenceDigest",
    "revocation.payload.revokedArtifacts[]",
];
const EVIDENCE_BUNDLE_INPUTS: &[&str] = &[
    "evidence.manifestDigest",
    "evidence.nativeClosureEnvelopeDigest",
    "evidence.helperArtifactDigest",
    "evidence.helperIncarnation",
    "evidence.protocolDigest",
    "evidence.requestDigest",
    "evidence.b3ProfileEnvelopeDigest",
    "evidence.b3LeaseReceiptEnvelopeDigest",
    "evidence.proberArtifactDigest",
    "evidence.proberIncarnation",
    "evidence.revocationEnvelopeDigest",
    "evidence.roles[].artifactDigest",
    "evidence.roles[].incarnationDigest",
    "evidence.measurements[].value.ioMaxDigest",
    "evidence.measurements[].value.filterDigest",
    "evidence.measurements[].value.rulesetDigest",
    "evidence.measurements[].value.entries[].sourceDigest",
    "evidence.measurements[].value.entries[].flagsDigest",
    "evidence.measurements[].value.pidfdDigest",
    "evidence.measurements[].value.value",
    "evidence.measurements[].value.values[]",
    "evidence.measurements[].transcriptDigest",
    "evidence.negativeProbes[].controlDigest",
    "evidence.inheritedFdInventory[].flagsDigest",
    "evidence.cleanup.journalDigest",
    "evidence.previousEvidenceDigest",
];
const REVOCATION_PAYLOAD_INPUTS: &[&str] = &[
    "revocation.payload.previousEnvelopeDigest",
    "revocation.payload.revokedArtifacts[]",
];
const REQUIRED_DAG_EDGES: &[(&str, &[&str])] = &[
    (
        "deployment.payload.deploymentBaseDigest",
        DEPLOYMENT_BASE_INPUTS,
    ),
    (
        "deployment.payload.rollback.authorizedRollbackEnvelopeDigest",
        &["deployment.payload.deploymentBaseDigest"],
    ),
    ("deployment.payloadDigest", DEPLOYMENT_PAYLOAD_INPUTS),
    ("request.manifestDigest", &["deployment.payloadDigest"]),
    ("evidence.manifestDigest", &["deployment.payloadDigest"]),
    (
        "closure.payload.nativeDeploymentEnvelopeDigest",
        &["deployment.payloadDigest"],
    ),
    (
        "index.payload.deploymentEnvelopeDigest",
        &["deployment.payloadDigest"],
    ),
    (
        "closure.payload.nativeClosureBaseDigest",
        CLOSURE_BASE_INPUTS,
    ),
    (
        "closure.payload.timestampRecordEnvelopeDigest",
        &["closure.payload.nativeClosureBaseDigest"],
    ),
    ("closure.payloadDigest", CLOSURE_PAYLOAD_INPUTS),
    (
        "index.payload.nativeClosureEnvelopeDigest",
        &["closure.payloadDigest"],
    ),
    (
        "evidence.nativeClosureEnvelopeDigest",
        &["closure.payloadDigest"],
    ),
    ("index.payloadDigest", INDEX_PAYLOAD_INPUTS),
    ("revocation.payloadDigest", REVOCATION_PAYLOAD_INPUTS),
    ("response.evidenceBundleDigest", EVIDENCE_BUNDLE_INPUTS),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestRegistryEntry {
    pub path: &'static str,
    pub field: &'static str,
    pub semantic_type: &'static str,
    pub rank: u8,
    pub depends_on: &'static [&'static str],
}

fn digest_registry_leaf(
    path: &'static str,
    semantic_type: Option<&'static str>,
) -> DigestRegistryEntry {
    let (rank, depends_on): (u8, &'static [&'static str]) = if path == "revocation.payloadDigest" {
        (1, &["revocation.payload.previousEnvelopeDigest"])
    } else if path.ends_with("authorizedRollbackEnvelopeDigest") {
        (4, &["deployment.payload.deploymentBaseDigest"])
    } else if path == "request.manifestDigest"
        || path == "evidence.manifestDigest"
        || path.ends_with("deploymentEnvelopeDigest")
        || path.ends_with("nativeDeploymentEnvelopeDigest")
    {
        (6, &["deployment.payloadDigest"])
    } else if path.ends_with("timestampRecordEnvelopeDigest") {
        (8, &["closure.payload.nativeClosureBaseDigest"])
    } else if path.ends_with("nativeClosureEnvelopeDigest") {
        (10, &["closure.payloadDigest"])
    } else {
        (0, &[])
    };
    let tail = path.rsplit('.').next().unwrap_or(path);
    let field = tail.strip_suffix("[]").unwrap_or(tail);
    let semantic_type = semantic_type.unwrap_or_else(|| {
        if path == "request.manifestDigest"
            || path == "evidence.manifestDigest"
            || path.ends_with("deploymentEnvelopeDigest")
            || path.ends_with("nativeDeploymentEnvelopeDigest")
        {
            "native-deployment-envelope-v1"
        } else if path.ends_with("nativeClosureEnvelopeDigest") {
            "native-release-closure-envelope-v1"
        } else {
            path
        }
    });
    DigestRegistryEntry {
        path,
        field,
        semantic_type,
        rank,
        depends_on,
    }
}

pub static NATIVE_V2_DIGEST_REGISTRY: std::sync::LazyLock<Vec<DigestRegistryEntry>> =
    std::sync::LazyLock::new(|| {
        let mut entries = Vec::new();
        entries.extend(
            DEPLOYMENT_BASE_INPUTS
                .iter()
                .map(|path| digest_registry_leaf(path, None)),
        );
        entries.push(digest_registry_leaf(
            "deployment.payload.rollback.authorizedRollbackEnvelopeDigest",
            None,
        ));
        entries.push(DigestRegistryEntry {
            path: "deployment.payload.deploymentBaseDigest",
            field: "deploymentBaseDigest",
            semantic_type: "native-deployment-base-v1",
            rank: 3,
            depends_on: DEPLOYMENT_BASE_INPUTS,
        });
        entries.extend(
            CLOSURE_BASE_INPUTS
                .iter()
                .map(|path| digest_registry_leaf(path, None)),
        );
        entries.push(digest_registry_leaf(
            "closure.payload.timestampRecordEnvelopeDigest",
            None,
        ));
        entries.push(DigestRegistryEntry {
            path: "closure.payload.nativeClosureBaseDigest",
            field: "nativeClosureBaseDigest",
            semantic_type: "native-release-closure-base-v1",
            rank: 7,
            depends_on: CLOSURE_BASE_INPUTS,
        });
        entries.extend(OTHER_DIGEST_PATHS.iter().map(|path| match *path {
            "deployment.payloadDigest" => DigestRegistryEntry {
                path,
                field: "payloadDigest",
                semantic_type: "native-deployment-payload-v1",
                rank: 5,
                depends_on: DEPLOYMENT_PAYLOAD_INPUTS,
            },
            "closure.payloadDigest" => DigestRegistryEntry {
                path,
                field: "payloadDigest",
                semantic_type: "native-release-closure-payload-v1",
                rank: 9,
                depends_on: CLOSURE_PAYLOAD_INPUTS,
            },
            "index.payloadDigest" => DigestRegistryEntry {
                path,
                field: "payloadDigest",
                semantic_type: "native-release-index-payload-v1",
                rank: 11,
                depends_on: INDEX_PAYLOAD_INPUTS,
            },
            "revocation.payloadDigest" => DigestRegistryEntry {
                path,
                field: "payloadDigest",
                semantic_type: "native-revocation-payload-v1",
                rank: 1,
                depends_on: REVOCATION_PAYLOAD_INPUTS,
            },
            "response.evidenceBundleDigest" => DigestRegistryEntry {
                path,
                field: "evidenceBundleDigest",
                semantic_type: "native-evidence-bundle-v1",
                rank: 12,
                depends_on: EVIDENCE_BUNDLE_INPUTS,
            },
            _ => digest_registry_leaf(path, None),
        }));
        entries
    });

pub fn validate_digest_registry(entries: &[DigestRegistryEntry]) -> Result<(), ProtocolError> {
    let mut by_path = std::collections::BTreeMap::new();
    for entry in entries {
        if entry.path.is_empty() || entry.field.is_empty() || entry.semantic_type.is_empty() {
            return Err(ProtocolError("digest registry identity empty"));
        }
        if by_path.insert(entry.path, entry.rank).is_some() {
            return Err(ProtocolError("digest registry path duplicate"));
        }
    }
    for entry in entries {
        for dependency in entry.depends_on {
            let dependency_rank = by_path
                .get(dependency)
                .ok_or(ProtocolError("digest registry dependency absent"))?;
            if *dependency_rank >= entry.rank {
                return Err(ProtocolError("digest registry dependency rank invalid"));
            }
        }
        if let Some((_, required)) = REQUIRED_DAG_EDGES
            .iter()
            .find(|(path, _)| *path == entry.path)
        {
            let mut actual = entry.depends_on.to_vec();
            let mut expected = required.to_vec();
            actual.sort_unstable();
            expected.sort_unstable();
            if actual != expected {
                return Err(ProtocolError("digest registry required edges incomplete"));
            }
        }
    }
    for (required_path, _) in REQUIRED_DAG_EDGES {
        if !by_path.contains_key(required_path) {
            return Err(ProtocolError("digest registry required node absent"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_items: usize,
    pub max_collection_items: usize,
    pub max_text_bytes: usize,
}

impl Limits {
    pub const WIRE: Self = Self {
        max_bytes: 1_048_576,
        max_depth: 16,
        max_items: 65536,
        max_collection_items: 1024,
        max_text_bytes: 4096,
    };
    pub const MANIFEST: Self = Self {
        max_bytes: 4 * 1024 * 1024,
        max_depth: 16,
        max_items: 65536,
        max_collection_items: 1024,
        max_text_bytes: 4096,
    };
    pub const EVIDENCE: Self = Self {
        max_bytes: 8 * 1024 * 1024,
        max_depth: 16,
        max_items: 65536,
        max_collection_items: 1024,
        max_text_bytes: 4096,
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Unsigned(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
}

impl Value {
    pub fn field(&self, name: &str) -> Option<&Value> {
        match self {
            Self::Map(entries) => entries
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(*value),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolError(pub &'static str);
impl Display for ProtocolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ProtocolError {}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    limits: Limits,
    items: usize,
}
impl<'a> Parser<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .at
            .checked_add(count)
            .ok_or(ProtocolError("length overflow"))?;
        let out = self
            .bytes
            .get(self.at..end)
            .ok_or(ProtocolError("truncated CBOR"))?;
        self.at = end;
        Ok(out)
    }
    fn argument(&mut self, additional: u8) -> Result<u64, ProtocolError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.take(1)?[0]);
                if value < 24 {
                    Err(ProtocolError("non-shortest integer"))
                } else {
                    Ok(value)
                }
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(
                    self.take(2)?
                        .try_into()
                        .map_err(|_| ProtocolError("truncated CBOR"))?,
                ));
                if value <= u64::from(u8::MAX) {
                    Err(ProtocolError("non-shortest integer"))
                } else {
                    Ok(value)
                }
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(
                    self.take(4)?
                        .try_into()
                        .map_err(|_| ProtocolError("truncated CBOR"))?,
                ));
                if value <= u64::from(u16::MAX) {
                    Err(ProtocolError("non-shortest integer"))
                } else {
                    Ok(value)
                }
            }
            27 => {
                let value = u64::from_be_bytes(
                    self.take(8)?
                        .try_into()
                        .map_err(|_| ProtocolError("truncated CBOR"))?,
                );
                if value <= u64::from(u32::MAX) {
                    Err(ProtocolError("non-shortest integer"))
                } else {
                    Ok(value)
                }
            }
            _ => Err(ProtocolError("indefinite/reserved CBOR length")),
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, ProtocolError> {
        if depth > self.limits.max_depth {
            return Err(ProtocolError("CBOR depth exceeds bound"));
        }
        self.items = self
            .items
            .checked_add(1)
            .ok_or(ProtocolError("item count overflow"))?;
        if self.items > self.limits.max_items {
            return Err(ProtocolError("CBOR item count exceeds bound"));
        }
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let additional = initial & 31;
        match major {
            0 => Ok(Value::Unsigned(self.argument(additional)?)),
            1 => Err(ProtocolError("negative integers are not admitted")),
            2 => {
                let len = usize::try_from(self.argument(additional)?)
                    .map_err(|_| ProtocolError("byte length overflow"))?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = usize::try_from(self.argument(additional)?)
                    .map_err(|_| ProtocolError("text length overflow"))?;
                if len > self.limits.max_text_bytes {
                    return Err(ProtocolError("text exceeds bound"));
                }
                let text = std::str::from_utf8(self.take(len)?)
                    .map_err(|_| ProtocolError("invalid UTF-8"))?;
                if !text
                    .bytes()
                    .all(|byte| byte == b'\n' || (0x20..=0x7e).contains(&byte))
                {
                    return Err(ProtocolError("text is outside the native ASCII profile"));
                }
                Ok(Value::Text(text.to_owned()))
            }
            4 => {
                let len = usize::try_from(self.argument(additional)?)
                    .map_err(|_| ProtocolError("array length overflow"))?;
                if len > self.limits.max_collection_items
                    || self
                        .items
                        .checked_add(len)
                        .ok_or(ProtocolError("item count overflow"))?
                        > self.limits.max_items
                {
                    return Err(ProtocolError("array exceeds bound"));
                }
                let mut out = Vec::with_capacity(len);
                for _ in 0..len {
                    out.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(out))
            }
            5 => {
                let len = usize::try_from(self.argument(additional)?)
                    .map_err(|_| ProtocolError("map length overflow"))?;
                if len > self.limits.max_collection_items
                    || self
                        .items
                        .checked_add(len.saturating_mul(2))
                        .ok_or(ProtocolError("item count overflow"))?
                        > self.limits.max_items
                {
                    return Err(ProtocolError("map exceeds bound"));
                }
                let mut out = Vec::with_capacity(len);
                let mut prior: Option<Vec<u8>> = None;
                for _ in 0..len {
                    let start = self.at;
                    let key = self.value(depth + 1)?;
                    let encoded_key = self.bytes[start..self.at].to_vec();
                    if let Some(previous) = &prior {
                        if canonical_key_cmp(previous, &encoded_key) != Ordering::Less {
                            return Err(ProtocolError("map keys are duplicated or noncanonical"));
                        }
                    }
                    prior = Some(encoded_key);
                    let key = match key {
                        Value::Text(value) => value,
                        _ => return Err(ProtocolError("map key is not text")),
                    };
                    out.push((key, self.value(depth + 1)?));
                }
                Ok(Value::Map(out))
            }
            6 => Err(ProtocolError("CBOR tags are not admitted")),
            7 if additional == 20 => Ok(Value::Bool(false)),
            7 if additional == 21 => Ok(Value::Bool(true)),
            7 if additional == 22 => Ok(Value::Null),
            7 => Err(ProtocolError("floats/simple values are not admitted")),
            _ => Err(ProtocolError("unsupported CBOR major type")),
        }
    }
}

fn canonical_key_cmp(left: &[u8], right: &[u8]) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}
fn head(major: u8, value: u64, out: &mut Vec<u8>) {
    if value < 24 {
        out.push((major << 5) | value as u8);
    } else if u8::try_from(value).is_ok() {
        out.extend_from_slice(&[(major << 5) | 24, value as u8]);
    } else if u16::try_from(value).is_ok() {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if u32::try_from(value).is_ok() {
        out.push((major << 5) | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

pub fn encode_bounded(value: &Value, limits: Limits) -> Result<Vec<u8>, ProtocolError> {
    let mut items = 0usize;
    let encoded_len = validate_value_bounds(value, 0, &mut items, limits)?;
    let mut out = Vec::with_capacity(encoded_len);
    encode_into(value, &mut out)?;
    if out.len() != encoded_len {
        return Err(ProtocolError("encoded CBOR length accounting mismatch"));
    }
    Ok(out)
}
fn head_len(value: usize) -> usize {
    if value < 24 {
        1
    } else if u8::try_from(value).is_ok() {
        2
    } else if u16::try_from(value).is_ok() {
        3
    } else if u32::try_from(value).is_ok() {
        5
    } else {
        9
    }
}
fn bounded_add(left: usize, right: usize, limits: Limits) -> Result<usize, ProtocolError> {
    let total = left
        .checked_add(right)
        .ok_or(ProtocolError("encoded length overflow"))?;
    if total > limits.max_bytes {
        Err(ProtocolError("encoded CBOR exceeds byte bound"))
    } else {
        Ok(total)
    }
}
fn validate_value_bounds(
    value: &Value,
    depth: usize,
    items: &mut usize,
    limits: Limits,
) -> Result<usize, ProtocolError> {
    if depth > limits.max_depth {
        return Err(ProtocolError("CBOR depth exceeds bound"));
    }
    *items = items
        .checked_add(1)
        .ok_or(ProtocolError("item count overflow"))?;
    if *items > limits.max_items {
        return Err(ProtocolError("CBOR item count exceeds bound"));
    }
    let encoded = match value {
        Value::Text(text) => {
            if text.len() > limits.max_text_bytes {
                return Err(ProtocolError("text exceeds bound"));
            }
            if !text
                .bytes()
                .all(|byte| byte == b'\n' || (0x20..=0x7e).contains(&byte))
            {
                return Err(ProtocolError("text is outside the native ASCII profile"));
            }
            bounded_add(head_len(text.len()), text.len(), limits)?
        }
        Value::Bytes(bytes) => bounded_add(head_len(bytes.len()), bytes.len(), limits)?,
        Value::Array(values) => {
            if values.len() > limits.max_collection_items {
                return Err(ProtocolError("array exceeds bound"));
            }
            let mut total = head_len(values.len());
            for value in values {
                total = bounded_add(
                    total,
                    validate_value_bounds(value, depth + 1, items, limits)?,
                    limits,
                )?;
            }
            total
        }
        Value::Map(entries) => {
            if entries.len() > limits.max_collection_items {
                return Err(ProtocolError("map exceeds bound"));
            }
            let mut total = head_len(entries.len());
            for (key, value) in entries {
                total = bounded_add(
                    total,
                    validate_value_bounds(&Value::Text(key.clone()), depth + 1, items, limits)?,
                    limits,
                )?;
                total = bounded_add(
                    total,
                    validate_value_bounds(value, depth + 1, items, limits)?,
                    limits,
                )?;
            }
            total
        }
        Value::Unsigned(value) => head_len(usize::try_from(*value).unwrap_or(usize::MAX)),
        _ => 1,
    };
    if encoded > limits.max_bytes {
        return Err(ProtocolError("encoded CBOR exceeds byte bound"));
    }
    Ok(encoded)
}
fn encode_into(value: &Value, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
    match value {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Unsigned(value) => head(0, *value, out),
        Value::Bytes(value) => {
            head(2, value.len() as u64, out);
            out.extend_from_slice(value);
        }
        Value::Text(value) => {
            if !value
                .bytes()
                .all(|byte| byte == b'\n' || (0x20..=0x7e).contains(&byte))
            {
                return Err(ProtocolError("text is outside the native ASCII profile"));
            }
            head(3, value.len() as u64, out);
            out.extend_from_slice(value.as_bytes());
        }
        Value::Array(values) => {
            head(4, values.len() as u64, out);
            for value in values {
                encode_into(value, out)?;
            }
        }
        Value::Map(entries) => {
            let mut ordered = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let mut encoded = Vec::new();
                encode_into(&Value::Text(key.clone()), &mut encoded)?;
                ordered.push((encoded, value));
            }
            ordered.sort_by(|left, right| canonical_key_cmp(&left.0, &right.0));
            if ordered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(ProtocolError("duplicate map key"));
            }
            head(5, ordered.len() as u64, out);
            for (key, value) in ordered {
                out.extend_from_slice(&key);
                encode_into(value, out)?;
            }
        }
    }
    Ok(())
}

pub fn decode_canonical(bytes: &[u8], limits: Limits) -> Result<Value, ProtocolError> {
    if bytes.is_empty() || bytes.len() > limits.max_bytes {
        return Err(ProtocolError("CBOR byte length is invalid"));
    }
    let mut parser = Parser {
        bytes,
        at: 0,
        limits,
        items: 0,
    };
    let value = parser.value(0)?;
    if parser.at != bytes.len() {
        return Err(ProtocolError("trailing CBOR bytes"));
    }
    if encode_bounded(&value, limits)?.as_slice() != bytes {
        return Err(ProtocolError("CBOR is not canonical"));
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Schema {
    Request,
    Response,
    Deployment,
    NativeClosure,
    NativeIndex,
    Evidence,
    Revocation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustClass {
    Production,
    Development,
}

fn exact_keys(value: &Value, expected: &[&str]) -> Result<(), ProtocolError> {
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err(ProtocolError("schema root is not a map")),
    };
    if entries.len() != expected.len()
        || expected
            .iter()
            .any(|key| !entries.iter().any(|(actual, _)| actual == key))
    {
        return Err(ProtocolError("schema fields are not exact"));
    }
    Ok(())
}

fn projection_without(value: &Value, excluded: &[&str]) -> Result<Value, ProtocolError> {
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err(ProtocolError("projection source is not a map")),
    };
    Ok(Value::Map(
        entries
            .iter()
            .filter(|(key, _)| !excluded.contains(&key.as_str()))
            .cloned()
            .collect(),
    ))
}

fn projection_digest(domain: &[u8], projection: &Value) -> Result<String, ProtocolError> {
    let canonical = encode_bounded(projection, Limits::MANIFEST)?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

pub fn deployment_base_digest(value: &Value) -> Result<String, ProtocolError> {
    exact_keys(value, DEPLOYMENT_PAYLOAD_KEYS)?;
    let rollback = field(value, "rollback")?;
    exact_keys(rollback, DEPLOYMENT_ROLLBACK_KEYS)?;
    let rollback_projection = projection_without(rollback, &["authorizedRollbackEnvelopeDigest"])?;
    let mut projection = projection_without(value, &["deploymentBaseDigest"])?;
    let Value::Map(fields) = &mut projection else {
        unreachable!();
    };
    let rollback = fields
        .iter_mut()
        .find(|(key, _)| key == "rollback")
        .ok_or(ProtocolError("rollback missing from deployment projection"))?;
    rollback.1 = rollback_projection;
    projection_digest(b"keep.native-deployment-base/v1\0", &projection)
}

pub fn native_closure_base_digest(value: &Value) -> Result<String, ProtocolError> {
    exact_keys(value, NATIVE_CLOSURE_PAYLOAD_KEYS)?;
    let projection = projection_without(
        value,
        &["nativeClosureBaseDigest", "timestampRecordEnvelopeDigest"],
    )?;
    projection_digest(b"keep.native-release-closure-base/v1\0", &projection)
}
fn require_text(value: &Value, key: &str, expected: &str) -> Result<(), ProtocolError> {
    if value.field(key).and_then(Value::as_text) == Some(expected) {
        Ok(())
    } else {
        Err(ProtocolError("schema discriminator mismatch"))
    }
}
fn require_version(value: &Value, version: u64) -> Result<(), ProtocolError> {
    if value.field("version").and_then(Value::as_u64) == Some(version) {
        Ok(())
    } else {
        Err(ProtocolError("schema version mismatch"))
    }
}
fn identifier(value: &Value) -> Result<&str, ProtocolError> {
    let text = value
        .as_text()
        .ok_or(ProtocolError("identifier is not text"))?;
    if text.is_empty()
        || text.len() > 128
        || !text.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && b"._:@/-".contains(&byte))
        })
    {
        return Err(ProtocolError("identifier is malformed"));
    }
    Ok(text)
}
fn digest(value: &Value) -> Result<&str, ProtocolError> {
    let text = value.as_text().ok_or(ProtocolError("digest is not text"))?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || text.bytes().all(|byte| byte == b'0')
    {
        return Err(ProtocolError("digest is malformed"));
    }
    Ok(text)
}
fn signature_bytes(value: &Value) -> Result<(), ProtocolError> {
    match value {
        Value::Bytes(bytes) if bytes.len() == 64 && !bytes.iter().all(|byte| *byte == 0) => Ok(()),
        _ => Err(ProtocolError("Ed25519 signature bytes malformed")),
    }
}
fn array(value: &Value, maximum: usize) -> Result<&[Value], ProtocolError> {
    match value {
        Value::Array(values) if values.len() <= maximum => Ok(values),
        _ => Err(ProtocolError("array is malformed or oversized")),
    }
}
fn unique_text(values: &[Value]) -> Result<(), ProtocolError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if !seen.insert(identifier(value)?) {
            return Err(ProtocolError("identifier array contains duplicates"));
        }
    }
    Ok(())
}
fn require_trust(value: &Value, trust: TrustClass) -> Result<(), ProtocolError> {
    let expected = match trust {
        TrustClass::Production => "production",
        TrustClass::Development => "development",
    };
    if value.field("trustClass").and_then(Value::as_text) == Some(expected) {
        Ok(())
    } else {
        Err(ProtocolError("trust class refused"))
    }
}
fn payload<'a>(
    value: &'a Value,
    keys: &[&str],
    schema: &str,
    trust: Option<TrustClass>,
) -> Result<&'a Value, ProtocolError> {
    exact_keys(value, &["payload", "payloadDigest", "signatures"])?;
    let payload = value
        .field("payload")
        .ok_or(ProtocolError("payload missing"))?;
    exact_keys(payload, keys)?;
    require_text(payload, "schema", schema)?;
    require_version(payload, 1)?;
    if let Some(trust) = trust {
        require_trust(payload, trust)?;
    }
    let expected = value
        .field("payloadDigest")
        .and_then(Value::as_text)
        .ok_or(ProtocolError("payload digest missing"))?;
    if expected != sha256_hex(&encode_bounded(payload, Limits::MANIFEST)?) {
        return Err(ProtocolError("payload digest mismatch"));
    }
    let signatures = match value.field("signatures") {
        Some(Value::Array(rows)) if !rows.is_empty() && rows.len() <= 32 => rows,
        _ => return Err(ProtocolError("signatures malformed")),
    };
    for signature in signatures {
        exact_keys(signature, &["keyId", "algorithm", "keyEpoch", "signature"])?;
        let key = identifier(
            signature
                .field("keyId")
                .ok_or(ProtocolError("signature key missing"))?,
        )?;
        if let Some(trust) = trust {
            match trust {
                TrustClass::Production if key.starts_with("development.") => {
                    return Err(ProtocolError("development signature key refused"));
                }
                TrustClass::Development if !key.starts_with("development.") => {
                    return Err(ProtocolError(
                        "development signature key namespace required",
                    ));
                }
                _ => {}
            }
        }
        require_text(signature, "algorithm", "ed25519")?;
        if signature
            .field("keyEpoch")
            .and_then(Value::as_u64)
            .is_none()
        {
            return Err(ProtocolError("signature epoch malformed"));
        }
        signature_bytes(
            signature
                .field("signature")
                .ok_or(ProtocolError("signature bytes missing"))?,
        )?;
    }
    Ok(payload)
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, ProtocolError> {
    value
        .field(key)
        .ok_or(ProtocolError("required field missing"))
}
fn uint_field(value: &Value, key: &str) -> Result<u64, ProtocolError> {
    field(value, key)?
        .as_u64()
        .ok_or(ProtocolError("uint64 field malformed"))
}
fn id_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProtocolError> {
    identifier(field(value, key)?)
}
fn digest_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProtocolError> {
    digest(field(value, key)?)
}
fn bool_field(value: &Value, key: &str) -> Result<bool, ProtocolError> {
    match field(value, key)? {
        Value::Bool(value) => Ok(*value),
        _ => Err(ProtocolError("boolean field malformed")),
    }
}
fn enum_field<'a>(value: &'a Value, key: &str, allowed: &[&str]) -> Result<&'a str, ProtocolError> {
    let found = id_field(value, key)?;
    if allowed.contains(&found) {
        Ok(found)
    } else {
        Err(ProtocolError("enum field unsupported"))
    }
}
fn sorted_ids(value: &Value, maximum: usize) -> Result<Vec<&str>, ProtocolError> {
    let values = array(value, maximum)?;
    let mut out = Vec::with_capacity(values.len());
    for item in values {
        out.push(identifier(item)?);
    }
    if out.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ProtocolError("identifier list is not sorted unique"));
    }
    Ok(out)
}
fn sorted_digests(value: &Value, maximum: usize) -> Result<Vec<&str>, ProtocolError> {
    let values = array(value, maximum)?;
    let mut out = Vec::with_capacity(values.len());
    for item in values {
        out.push(digest(item)?);
    }
    if out.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ProtocolError("digest list is not sorted unique"));
    }
    Ok(out)
}
fn exact_bool_map(value: &Value, keys: &[&str]) -> Result<(), ProtocolError> {
    exact_keys(value, keys)?;
    for key in keys {
        bool_field(value, key)?;
    }
    Ok(())
}
fn exact_uint_map(value: &Value, keys: &[&str]) -> Result<(), ProtocolError> {
    exact_keys(value, keys)?;
    for key in keys {
        uint_field(value, key)?;
    }
    Ok(())
}
fn require_key_namespace(key: &str, trust: TrustClass) -> Result<(), ProtocolError> {
    match trust {
        TrustClass::Production if key.starts_with("development.") => {
            Err(ProtocolError("development signature key refused"))
        }
        TrustClass::Development if !key.starts_with("development.") => Err(ProtocolError(
            "development signature key namespace required",
        )),
        _ => Ok(()),
    }
}
fn validate_envelope_key_namespaces(value: &Value, trust: TrustClass) -> Result<(), ProtocolError> {
    for signature in array(field(value, "signatures")?, 32)? {
        require_key_namespace(id_field(signature, "keyId")?, trust)?;
    }
    Ok(())
}
fn require_envelope_epoch(value: &Value, epoch: u64) -> Result<(), ProtocolError> {
    for signature in array(field(value, "signatures")?, 32)? {
        if uint_field(signature, "keyEpoch")? != epoch {
            return Err(ProtocolError("signature key epoch mismatch"));
        }
    }
    Ok(())
}
const MEASUREMENT_FIELDS: [&str; 27] = [
    "capture.window",
    "cgroup.limits",
    "credential.state",
    "fd.inventory",
    "identity.gid.effective",
    "identity.gid.real",
    "identity.gid.saved",
    "identity.groups",
    "identity.uid.effective",
    "identity.uid.real",
    "identity.uid.saved",
    "incarnation",
    "landlock.policy",
    "loader.executable",
    "loader.shared-libraries",
    "mount.topology",
    "namespaces.inodes",
    "network.topology",
    "seccomp.launch",
    "seccomp.steady",
    "security.capabilities.ambient",
    "security.capabilities.bounding",
    "security.capabilities.effective",
    "security.capabilities.inheritable",
    "security.capabilities.permitted",
    "security.dumpable",
    "security.no-new-privileges",
];
fn measurement_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProtocolError> {
    let field = id_field(value, key)?;
    if MEASUREMENT_FIELDS.contains(&field) {
        Ok(field)
    } else {
        Err(ProtocolError("measurement field outside registry"))
    }
}
fn uint_values(value: &Value, maximum: usize) -> Result<(), ProtocolError> {
    let values = array(value, maximum)?;
    let mut prior = None;
    for value in values {
        let current = value
            .as_u64()
            .ok_or(ProtocolError("uint64 set malformed"))?;
        if prior.is_some_and(|previous| previous >= current) {
            return Err(ProtocolError("uint64 set not sorted unique"));
        }
        prior = Some(current);
    }
    Ok(())
}
fn validate_measurement_value(field_name: &str, value: &Value) -> Result<(), ProtocolError> {
    if field_name.starts_with("identity.uid.") || field_name.starts_with("identity.gid.") {
        exact_keys(value, &["type", "value"])?;
        require_text(value, "type", "uint64")?;
        uint_field(value, "value")?;
        return Ok(());
    }
    if field_name == "identity.groups" {
        exact_keys(value, &["type", "values"])?;
        require_text(value, "type", "uint64-set")?;
        uint_values(field(value, "values")?, 64)?;
        return Ok(());
    }
    if field_name.starts_with("security.capabilities.") {
        exact_keys(value, &["type", "values"])?;
        require_text(value, "type", "identifier-set")?;
        sorted_ids(field(value, "values")?, 128)?;
        return Ok(());
    }
    if matches!(
        field_name,
        "security.dumpable" | "security.no-new-privileges"
    ) {
        exact_keys(value, &["type", "value"])?;
        require_text(value, "type", "boolean")?;
        bool_field(value, "value")?;
        return Ok(());
    }
    if field_name == "loader.executable" {
        exact_keys(value, &["type", "value"])?;
        require_text(value, "type", "digest")?;
        digest_field(value, "value")?;
        return Ok(());
    }
    if field_name == "loader.shared-libraries" {
        exact_keys(value, &["type", "values"])?;
        require_text(value, "type", "digest-set")?;
        sorted_digests(field(value, "values")?, 256)?;
        return Ok(());
    }
    if field_name == "namespaces.inodes" {
        exact_keys(
            value,
            &["type", "user", "pid", "mount", "network", "ipc", "cgroup"],
        )?;
        require_text(value, "type", "namespace-inodes")?;
        for key in ["user", "pid", "mount", "network", "ipc", "cgroup"] {
            uint_field(value, key)?;
        }
        return Ok(());
    }
    if field_name == "cgroup.limits" {
        exact_keys(
            value,
            &[
                "type",
                "memoryMax",
                "pidsMax",
                "cpuMaxMicros",
                "ioMaxDigest",
            ],
        )?;
        require_text(value, "type", "cgroup-limits")?;
        for key in ["memoryMax", "pidsMax", "cpuMaxMicros"] {
            uint_field(value, key)?;
        }
        digest_field(value, "ioMaxDigest")?;
        return Ok(());
    }
    if matches!(field_name, "seccomp.launch" | "seccomp.steady") {
        exact_keys(
            value,
            &[
                "type",
                "architecture",
                "defaultAction",
                "allowedActions",
                "filterDigest",
                "noNewPrivileges",
            ],
        )?;
        require_text(value, "type", "seccomp-policy")?;
        id_field(value, "architecture")?;
        id_field(value, "defaultAction")?;
        sorted_ids(field(value, "allowedActions")?, 256)?;
        digest_field(value, "filterDigest")?;
        if !bool_field(value, "noNewPrivileges")? {
            return Err(ProtocolError("seccomp lacks no-new-privileges"));
        }
        return Ok(());
    }
    if field_name == "landlock.policy" {
        exact_keys(
            value,
            &[
                "type",
                "abi",
                "handledRights",
                "scopedRights",
                "rulesetDigest",
            ],
        )?;
        require_text(value, "type", "landlock-policy")?;
        uint_field(value, "abi")?;
        sorted_ids(field(value, "handledRights")?, 256)?;
        sorted_ids(field(value, "scopedRights")?, 256)?;
        digest_field(value, "rulesetDigest")?;
        return Ok(());
    }
    if field_name == "mount.topology" {
        exact_keys(value, &["type", "entries"])?;
        require_text(value, "type", "mount-topology")?;
        for mount in array(field(value, "entries")?, 128)? {
            exact_keys(
                mount,
                &[
                    "target",
                    "sourceDigest",
                    "readOnly",
                    "nodev",
                    "nosuid",
                    "noexec",
                ],
            )?;
            let target = field(mount, "target")?
                .as_text()
                .ok_or(ProtocolError("mount target malformed"))?;
            if target.len() < 2
                || !target.starts_with('/')
                || target.contains("//")
                || target.split('/').any(|part| matches!(part, "." | ".."))
                || !target.bytes().all(|byte| {
                    byte == b'/' || byte.is_ascii_alphanumeric() || b"._@-".contains(&byte)
                })
            {
                return Err(ProtocolError("mount target malformed"));
            }
            digest_field(mount, "sourceDigest")?;
            for key in ["readOnly", "nodev", "nosuid", "noexec"] {
                bool_field(mount, key)?;
            }
        }
        return Ok(());
    }
    if field_name == "network.topology" {
        exact_keys(value, &["type", "interfaces", "routes", "addressFamilies"])?;
        require_text(value, "type", "network-topology")?;
        sorted_ids(field(value, "interfaces")?, 128)?;
        sorted_ids(field(value, "routes")?, 256)?;
        sorted_ids(field(value, "addressFamilies")?, 32)?;
        return Ok(());
    }
    if field_name == "fd.inventory" {
        exact_keys(value, &["type", "entries"])?;
        require_text(value, "type", "descriptor-inventory")?;
        for fd in array(field(value, "entries")?, 256)? {
            exact_keys(
                fd,
                &[
                    "slot",
                    "purpose",
                    "flagsDigest",
                    "seals",
                    "credentialDomain",
                ],
            )?;
            uint_field(fd, "slot")?;
            id_field(fd, "purpose")?;
            digest_field(fd, "flagsDigest")?;
            sorted_ids(field(fd, "seals")?, 32)?;
            if !matches!(field(fd, "credentialDomain")?, Value::Null) {
                id_field(fd, "credentialDomain")?;
            }
        }
        return Ok(());
    }
    if field_name == "credential.state" {
        exact_keys(
            value,
            &[
                "type",
                "domains",
                "deliveredAfterAttestation",
                "descriptorCount",
            ],
        )?;
        require_text(value, "type", "credential-state")?;
        sorted_ids(field(value, "domains")?, 32)?;
        if !bool_field(value, "deliveredAfterAttestation")? {
            return Err(ProtocolError("credential delivered before attestation"));
        }
        uint_field(value, "descriptorCount")?;
        return Ok(());
    }
    if field_name == "incarnation" {
        exact_keys(
            value,
            &["type", "pidfdDigest", "startCounter", "expiresCounter"],
        )?;
        require_text(value, "type", "incarnation")?;
        digest_field(value, "pidfdDigest")?;
        if uint_field(value, "expiresCounter")? < uint_field(value, "startCounter")? {
            return Err(ProtocolError("incarnation counter order invalid"));
        }
        return Ok(());
    }
    if field_name == "capture.window" {
        exact_keys(value, &["type", "capturedCounter", "expiresCounter"])?;
        require_text(value, "type", "counter-window")?;
        if uint_field(value, "expiresCounter")? < uint_field(value, "capturedCounter")? {
            return Err(ProtocolError("capture counter order invalid"));
        }
        return Ok(());
    }
    Err(ProtocolError("measurement field outside registry"))
}

fn validate_deployment(value: &Value) -> Result<(), ProtocolError> {
    id_field(value, "deploymentId")?;
    uint_field(value, "deploymentEpoch")?;
    digest_field(value, "deploymentBaseDigest")?;
    if digest_field(value, "deploymentBaseDigest")? != deployment_base_digest(value)? {
        return Err(ProtocolError("deployment base digest mismatch"));
    }
    digest_field(value, "predecessorDigest")?;
    let boot = field(value, "bootPolicy")?;
    exact_keys(
        boot,
        &[
            "maxLaunchMs",
            "maxResponseMs",
            "maxAttestationAge",
            "maxCleanupMs",
            "maxConcurrentTransactions",
            "kernelCells",
        ],
    )?;
    for key in [
        "maxLaunchMs",
        "maxResponseMs",
        "maxAttestationAge",
        "maxCleanupMs",
    ] {
        uint_field(boot, key)?;
    }
    if uint_field(boot, "maxConcurrentTransactions")? != 1 {
        return Err(ProtocolError("v1 concurrency must equal one"));
    }
    let cells = array(field(boot, "kernelCells")?, 32)?;
    if cells.is_empty() {
        return Err(ProtocolError("kernel cells empty"));
    }
    let mut cell_ids = Vec::new();
    for cell in cells {
        exact_keys(
            cell,
            &[
                "cellId",
                "minimumKernel",
                "maximumKernel",
                "requiredFeatures",
            ],
        )?;
        cell_ids.push(id_field(cell, "cellId")?);
        id_field(cell, "minimumKernel")?;
        id_field(cell, "maximumKernel")?;
        sorted_ids(field(cell, "requiredFeatures")?, 64)?;
    }
    if cell_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ProtocolError("kernel cells not sorted unique"));
    }
    let protocol = field(value, "protocol")?;
    exact_keys(
        protocol,
        &[
            "name",
            "version",
            "maxFrameBytes",
            "maxRoles",
            "maxChannels",
            "maxMeasurements",
            "maxDepth",
            "maxItems",
            "maxTextBytes",
        ],
    )?;
    require_text(protocol, "name", PROTOCOL_NAME)?;
    require_version(protocol, 2)?;
    for (key, expected) in [
        ("maxFrameBytes", 1_048_576),
        ("maxRoles", 32),
        ("maxChannels", 128),
        ("maxMeasurements", 1024),
        ("maxDepth", 16),
        ("maxItems", 65536),
        ("maxTextBytes", 4096),
    ] {
        if uint_field(protocol, key)? != expected {
            return Err(ProtocolError("protocol limit mismatch"));
        }
    }
    let artifacts = array(field(value, "artifacts")?, 128)?;
    if artifacts.is_empty() {
        return Err(ProtocolError("artifacts empty"));
    }
    let mut artifact_ids = std::collections::BTreeSet::new();
    let mut artifact_digests = std::collections::BTreeMap::new();
    let mut artifact_kinds = std::collections::BTreeMap::new();
    let mut prior = None;
    for artifact in artifacts {
        exact_keys(
            artifact,
            &[
                "artifactId",
                "digest",
                "kind",
                "targetTriple",
                "variant",
                "executableMode",
                "releaseMember",
            ],
        )?;
        let id = id_field(artifact, "artifactId")?;
        if prior.is_some_and(|previous| previous >= id) || !artifact_ids.insert(id) {
            return Err(ProtocolError("artifacts not sorted unique"));
        }
        prior = Some(id);
        let artifact_digest = digest_field(artifact, "digest")?;
        let artifact_kind = enum_field(
            artifact,
            "kind",
            &["helper", "trampoline", "prober", "provisioner", "role"],
        )?;
        artifact_digests.insert(id, artifact_digest);
        artifact_kinds.insert(id, artifact_kind);
        id_field(artifact, "targetTriple")?;
        id_field(artifact, "variant")?;
        if uint_field(artifact, "executableMode")? != 365 || !bool_field(artifact, "releaseMember")?
        {
            return Err(ProtocolError("artifact is not executable release member"));
        }
    }
    for kind in ["helper", "trampoline", "prober"] {
        if artifact_kinds
            .values()
            .filter(|found| **found == kind)
            .count()
            != 1
        {
            return Err(ProtocolError("native artifact cardinality invalid"));
        }
    }
    let roles = array(field(value, "roles")?, 32)?;
    if roles.is_empty() {
        return Err(ProtocolError("deployment roles empty"));
    }
    let mut role_ids = std::collections::BTreeSet::new();
    let mut role_classes = std::collections::BTreeMap::new();
    let mut role_credentials: std::collections::BTreeMap<&str, Vec<&str>> =
        std::collections::BTreeMap::new();
    let mut principals = std::collections::BTreeSet::new();
    let mut prior = None;
    for role in roles {
        exact_keys(
            role,
            &[
                "roleId",
                "roleClass",
                "principalId",
                "artifactId",
                "artifactDigest",
                "credentialDomains",
                "allowedChannelIds",
                "uid",
                "gid",
                "supplementaryGroups",
                "namespaces",
                "mounts",
                "cgroup",
                "rlimits",
                "capabilitiesEmpty",
                "dumpable",
                "launchSeccompDigest",
                "steadySeccompDigest",
                "landlockDigest",
                "environmentAllowlist",
                "inheritedFdSlots",
                "requiredMeasurementFields",
            ],
        )?;
        let role_id = id_field(role, "roleId")?;
        if prior.is_some_and(|previous| previous >= role_id) || !role_ids.insert(role_id) {
            return Err(ProtocolError("roles not sorted unique"));
        }
        prior = Some(role_id);
        let class = enum_field(role, "roleClass", &["D1", "D2", "D3", "PROBER"])?;
        if !principals.insert(id_field(role, "principalId")?) {
            return Err(ProtocolError("role principals duplicate"));
        }
        let role_artifact = id_field(role, "artifactId")?;
        if artifact_kinds.get(role_artifact) != Some(&"role") {
            return Err(ProtocolError("role artifact absent or wrong kind"));
        }
        if artifact_digests.get(role_artifact) != Some(&digest_field(role, "artifactDigest")?) {
            return Err(ProtocolError("role artifact digest mismatch"));
        }
        let credentials = sorted_ids(field(role, "credentialDomains")?, 1)?;
        if class != "D3" && !credentials.is_empty() {
            return Err(ProtocolError("credentials outside D3"));
        }
        role_classes.insert(role_id, class);
        role_credentials.insert(role_id, credentials);
        sorted_ids(field(role, "allowedChannelIds")?, 128)?;
        uint_field(role, "uid")?;
        uint_field(role, "gid")?;
        let groups = array(field(role, "supplementaryGroups")?, 32)?;
        for group in groups {
            if group.as_u64().is_none() {
                return Err(ProtocolError("group malformed"));
            }
        }
        exact_bool_map(
            field(role, "namespaces")?,
            &["user", "pid", "mount", "network", "ipc", "cgroup"],
        )?;
        for mount in array(field(role, "mounts")?, 128)? {
            exact_keys(
                mount,
                &[
                    "sourceArtifactId",
                    "target",
                    "readOnly",
                    "nodev",
                    "nosuid",
                    "noexec",
                ],
            )?;
            if !artifact_ids.contains(id_field(mount, "sourceArtifactId")?) {
                return Err(ProtocolError("mount artifact absent"));
            }
            let target = field(mount, "target")?
                .as_text()
                .ok_or(ProtocolError("mount path malformed"))?;
            if target.len() < 2
                || target.len() > 4096
                || !target.starts_with('/')
                || target.contains("//")
                || target.split('/').any(|part| matches!(part, "." | ".."))
                || !target.bytes().all(|byte| {
                    byte == b'/' || byte.is_ascii_alphanumeric() || b"._@-".contains(&byte)
                })
            {
                return Err(ProtocolError("mount path malformed"));
            }
            for key in ["readOnly", "nodev", "nosuid", "noexec"] {
                bool_field(mount, key)?;
            }
        }
        let cgroup = field(role, "cgroup")?;
        exact_keys(
            cgroup,
            &[
                "pathId",
                "memoryMax",
                "pidsMax",
                "cpuMaxMicros",
                "ioMaxDigest",
            ],
        )?;
        id_field(cgroup, "pathId")?;
        for key in ["memoryMax", "pidsMax", "cpuMaxMicros"] {
            uint_field(cgroup, key)?;
        }
        digest_field(cgroup, "ioMaxDigest")?;
        exact_uint_map(
            field(role, "rlimits")?,
            &["nofile", "nproc", "core", "fsize", "addressSpace"],
        )?;
        if !bool_field(role, "capabilitiesEmpty")? || bool_field(role, "dumpable")? {
            return Err(ProtocolError("role privilege booleans refuse"));
        }
        for key in [
            "launchSeccompDigest",
            "steadySeccompDigest",
            "landlockDigest",
        ] {
            digest_field(role, key)?;
        }
        sorted_ids(field(role, "environmentAllowlist")?, 64)?;
        for slot in array(field(role, "inheritedFdSlots")?, 64)? {
            if slot.as_u64().is_none() {
                return Err(ProtocolError("fd slot malformed"));
            }
        }
        let measurements = sorted_ids(field(role, "requiredMeasurementFields")?, 128)?;
        if measurements.as_slice() != MEASUREMENT_FIELDS {
            return Err(ProtocolError("required measurements empty"));
        }
    }
    let channels = array(field(value, "channels")?, 128)?;
    let mut channel_ids = std::collections::BTreeSet::new();
    let mut channel_endpoints = std::collections::BTreeMap::new();
    let mut channel_by_id = std::collections::BTreeMap::new();
    let mut prior = None;
    for channel in channels {
        exact_keys(
            channel,
            &[
                "channelId",
                "fromEndpoint",
                "toEndpoint",
                "socketType",
                "direction",
                "maxFrameBytes",
                "maxDescriptors",
                "peerCredentialPolicy",
                "oneShot",
            ],
        )?;
        let id = id_field(channel, "channelId")?;
        if prior.is_some_and(|previous| previous >= id) || !channel_ids.insert(id) {
            return Err(ProtocolError("channels not sorted unique"));
        }
        prior = Some(id);
        let from = id_field(channel, "fromEndpoint")?;
        let to = id_field(channel, "toEndpoint")?;
        if from == to {
            return Err(ProtocolError("channel self-loop refused"));
        }
        enum_field(channel, "socketType", &["seqpacket"])?;
        enum_field(channel, "direction", &["one-way", "request-response"])?;
        let frame = uint_field(channel, "maxFrameBytes")?;
        let descriptors = uint_field(channel, "maxDescriptors")?;
        if frame == 0 || frame > 1_048_576 || descriptors > 64 {
            return Err(ProtocolError("channel operational bounds invalid"));
        }
        channel_endpoints.insert(id, (from, to));
        channel_by_id.insert(id, channel);
        enum_field(channel, "peerCredentialPolicy", &["exact-principal"])?;
        bool_field(channel, "oneShot")?;
    }
    for role in roles {
        for channel in sorted_ids(field(role, "allowedChannelIds")?, 128)? {
            let endpoint = format!("role:{}", id_field(role, "roleId")?);
            if !channel_ids.contains(channel)
                || !channel_endpoints
                    .get(channel)
                    .is_some_and(|(from, to)| *from == endpoint || *to == endpoint)
            {
                return Err(ProtocolError("role channel absent"));
            }
        }
    }
    let probers = array(field(value, "probers")?, 1)?;
    if probers.len() != 1 {
        return Err(ProtocolError("exactly one prober required"));
    }
    let prober = &probers[0];
    exact_keys(
        prober,
        &[
            "proberId",
            "artifactId",
            "principalId",
            "signingKeyId",
            "keyEpoch",
            "channelId",
            "observationGrants",
            "requiredNegativeProbes",
        ],
    )?;
    id_field(prober, "proberId")?;
    if artifact_kinds.get(id_field(prober, "artifactId")?) != Some(&"prober") {
        return Err(ProtocolError("prober artifact absent or wrong kind"));
    }
    let prober_principal = id_field(prober, "principalId")?;
    if principals.contains(prober_principal) {
        return Err(ProtocolError("prober principal aliases role"));
    }
    id_field(prober, "signingKeyId")?;
    uint_field(prober, "keyEpoch")?;
    id_field(prober, "channelId")?;
    sorted_ids(field(prober, "observationGrants")?, 128)?;
    sorted_ids(field(prober, "requiredNegativeProbes")?, 128)?;
    let provisioners = array(field(value, "provisioners")?, 32)?;
    let mut domains = std::collections::BTreeSet::new();
    let mut provisioner_ids = std::collections::BTreeSet::new();
    let mut provisioner_principals = std::collections::BTreeSet::new();
    let mut provisioner_prior = None;
    for provisioner in provisioners {
        exact_keys(
            provisioner,
            &[
                "provisionerId",
                "domain",
                "principalId",
                "artifactId",
                "targetRoleId",
                "channelId",
                "descriptorType",
                "requiredSeals",
                "descriptorCount",
                "destructionDeadlineMs",
            ],
        )?;
        let provisioner_id = id_field(provisioner, "provisionerId")?;
        if provisioner_prior.is_some_and(|previous| previous >= provisioner_id)
            || !provisioner_ids.insert(provisioner_id)
        {
            return Err(ProtocolError("provisioners not sorted unique"));
        }
        provisioner_prior = Some(provisioner_id);
        if !domains.insert(id_field(provisioner, "domain")?) {
            return Err(ProtocolError("provisioner domain duplicate"));
        }
        let principal = id_field(provisioner, "principalId")?;
        if principals.contains(principal)
            || principal == prober_principal
            || !provisioner_principals.insert(principal)
        {
            return Err(ProtocolError("provisioner principal aliases"));
        }
        let target = id_field(provisioner, "targetRoleId")?;
        let domain = id_field(provisioner, "domain")?;
        let provision_channel = id_field(provisioner, "channelId")?;
        let target_endpoint = format!("role:{target}");
        let provision_endpoint = format!("provisioner:{provisioner_id}");
        if artifact_kinds.get(id_field(provisioner, "artifactId")?) != Some(&"provisioner")
            || role_classes.get(target) != Some(&"D3")
            || !channel_endpoints
                .get(provision_channel)
                .is_some_and(|(from, to)| *from == provision_endpoint && *to == target_endpoint)
        {
            return Err(ProtocolError("provisioner reference absent"));
        }
        if role_credentials.get(target).map(Vec::as_slice) != Some(&[domain][..]) {
            return Err(ProtocolError("provisioner domain mismatch"));
        }
        id_field(provisioner, "descriptorType")?;
        sorted_ids(field(provisioner, "requiredSeals")?, 16)?;
        if uint_field(provisioner, "descriptorCount")? != 1 {
            return Err(ProtocolError("descriptor count must equal one"));
        }
        let channel = channel_by_id
            .get(provision_channel)
            .ok_or(ProtocolError("provision channel absent"))?;
        if enum_field(channel, "direction", &["one-way"]).is_err()
            || uint_field(channel, "maxDescriptors")? != 1
            || !bool_field(channel, "oneShot")?
        {
            return Err(ProtocolError("provision channel topology mismatch"));
        }
        uint_field(provisioner, "destructionDeadlineMs")?;
    }
    let b3 = field(value, "b3")?;
    exact_keys(b3, DEPLOYMENT_B3_KEYS)?;
    id_field(b3, "authorityId")?;
    digest_field(b3, "genesisBaseDigest")?;
    digest_field(b3, "b3ProfileEnvelopeDigest")?;
    uint_field(b3, "keyEpoch")?;
    enum_field(b3, "assurance", &["load-bearing"])?;
    id_field(b3, "channelId")?;
    let mut endpoints = std::collections::BTreeSet::new();
    endpoints.insert("supervisor:keep".to_owned());
    for role in roles {
        endpoints.insert(format!("role:{}", id_field(role, "roleId")?));
    }
    endpoints.insert(format!("prober:{}", id_field(prober, "proberId")?));
    endpoints.insert(format!("b3:{}", id_field(b3, "authorityId")?));
    for provisioner in provisioners {
        endpoints.insert(format!(
            "provisioner:{}",
            id_field(provisioner, "provisionerId")?
        ));
    }
    for (from, to) in channel_endpoints.values() {
        if !endpoints.contains(*from) || !endpoints.contains(*to) {
            return Err(ProtocolError("channel endpoint outside typed topology"));
        }
    }
    let prober_channel = channel_by_id
        .get(id_field(prober, "channelId")?)
        .ok_or(ProtocolError("prober channel absent"))?;
    if id_field(prober_channel, "fromEndpoint")?
        != format!("prober:{}", id_field(prober, "proberId")?)
        || id_field(prober_channel, "toEndpoint")? != "supervisor:keep"
        || enum_field(prober_channel, "direction", &["request-response"]).is_err()
        || uint_field(prober_channel, "maxDescriptors")? != 0
        || bool_field(prober_channel, "oneShot")?
    {
        return Err(ProtocolError("prober channel topology mismatch"));
    }
    let b3_channel = channel_by_id
        .get(id_field(b3, "channelId")?)
        .ok_or(ProtocolError("B3 channel absent"))?;
    if id_field(b3_channel, "fromEndpoint")? != "supervisor:keep"
        || id_field(b3_channel, "toEndpoint")? != format!("b3:{}", id_field(b3, "authorityId")?)
        || enum_field(b3_channel, "direction", &["request-response"]).is_err()
        || uint_field(b3_channel, "maxDescriptors")? != 0
        || bool_field(b3_channel, "oneShot")?
    {
        return Err(ProtocolError("B3 channel topology mismatch"));
    }
    let authority_channels: std::collections::BTreeSet<&str> =
        std::iter::once(id_field(prober, "channelId")?)
            .chain(std::iter::once(id_field(b3, "channelId")?))
            .chain(
                provisioners
                    .iter()
                    .map(|row| id_field(row, "channelId").unwrap_or("")),
            )
            .collect();
    for channel in channels {
        let channel_id = id_field(channel, "channelId")?;
        let from = id_field(channel, "fromEndpoint")?;
        let to = id_field(channel, "toEndpoint")?;
        let participants: Vec<&Value> = roles
            .iter()
            .filter(|role| {
                let endpoint = format!("role:{}", id_field(role, "roleId").unwrap_or(""));
                from == endpoint || to == endpoint
            })
            .collect();
        if !authority_channels.contains(channel_id) && participants.is_empty() {
            return Err(ProtocolError(
                "channel has no declared owner or authority purpose",
            ));
        }
        for role in participants {
            if !sorted_ids(field(role, "allowedChannelIds")?, 128)?.contains(&channel_id) {
                return Err(ProtocolError(
                    "channel grants an undeclared role participant",
                ));
            }
        }
    }
    let mut used_artifacts = std::collections::BTreeSet::new();
    for artifact in artifacts
        .iter()
        .filter(|row| matches!(id_field(row, "kind"), Ok("helper" | "trampoline")))
    {
        used_artifacts.insert(id_field(artifact, "artifactId")?);
    }
    used_artifacts.insert(id_field(prober, "artifactId")?);
    for role in roles {
        used_artifacts.insert(id_field(role, "artifactId")?);
    }
    for provisioner in provisioners {
        used_artifacts.insert(id_field(provisioner, "artifactId")?);
    }
    if used_artifacts.len() != artifacts.len()
        || artifact_ids.iter().any(|id| !used_artifacts.contains(id))
    {
        return Err(ProtocolError(
            "orphan or multiply-purposed artifact refused",
        ));
    }
    let release = field(value, "release")?;
    exact_keys(
        release,
        &[
            "buildId",
            "artifactVersion",
            "targetTriple",
            "variant",
            "releaseKeyEpoch",
            "timestampKeyEpoch",
        ],
    )?;
    id_field(release, "buildId")?;
    let artifact_version = uint_field(release, "artifactVersion")?;
    let release_target = id_field(release, "targetTriple")?;
    let release_variant = id_field(release, "variant")?;
    for artifact in artifacts {
        if id_field(artifact, "targetTriple")? != release_target
            || id_field(artifact, "variant")? != release_variant
        {
            return Err(ProtocolError("release target or variant mismatch"));
        }
    }
    uint_field(release, "releaseKeyEpoch")?;
    uint_field(release, "timestampKeyEpoch")?;
    let revocation = field(value, "revocation")?;
    exact_keys(revocation, DEPLOYMENT_REVOCATION_KEYS)?;
    for key in ["authorityId", "namespace", "scope", "compromiseSemantics"] {
        id_field(revocation, key)?;
    }
    uint_field(revocation, "keyEpoch")?;
    digest_field(revocation, "genesisCheckpointEnvelopeDigest")?;
    uint_field(revocation, "minimumSequence")?;
    uint_field(revocation, "maxStalenessCounters")?;
    let rollback = field(value, "rollback")?;
    exact_keys(rollback, DEPLOYMENT_ROLLBACK_KEYS)?;
    if uint_field(rollback, "deploymentEpoch")? != uint_field(value, "deploymentEpoch")?
        || uint_field(rollback, "minimumArtifactVersion")? > artifact_version
    {
        return Err(ProtocolError("rollback epoch or version mismatch"));
    }
    digest_field(rollback, "predecessorDigest")?;
    digest_field(rollback, "authorizedRollbackEnvelopeDigest")?;
    let evidence = field(value, "evidence")?;
    exact_keys(
        evidence,
        &[
            "schema",
            "sinkId",
            "maxBundleBytes",
            "algorithm",
            "keyId",
            "keyEpoch",
            "appendPolicy",
            "witnessPolicy",
        ],
    )?;
    require_text(evidence, "schema", "keep.native-evidence")?;
    id_field(evidence, "sinkId")?;
    if uint_field(evidence, "maxBundleBytes")? != 8 * 1024 * 1024 {
        return Err(ProtocolError("evidence bundle bound mismatch"));
    }
    require_text(evidence, "algorithm", "ed25519")?;
    if id_field(evidence, "keyId")? != id_field(prober, "signingKeyId")?
        || uint_field(evidence, "keyEpoch")? != uint_field(prober, "keyEpoch")?
    {
        return Err(ProtocolError("evidence key/prober mismatch"));
    }
    require_text(evidence, "appendPolicy", "create-exclusive-fsync")?;
    require_text(evidence, "witnessPolicy", "external-prober")?;
    Ok(())
}

fn validate_closure(value: &Value) -> Result<(), ProtocolError> {
    for key in [
        "a4ReleaseBaseDigest",
        "a4ArtifactInventoryDigest",
        "nativeArtifactInventoryDigest",
        "nativeDeploymentPayloadDigest",
        "nativeDeploymentEnvelopeDigest",
        "nativePackagePayloadDigest",
        "nativeClosureBaseDigest",
        "helperArtifactDigest",
        "trampolineArtifactDigest",
        "proberArtifactDigest",
        "protocolDigest",
        "evidenceSchemaDigest",
        "timestampRecordEnvelopeDigest",
        "sbomEnvelopeDigest",
        "reproducibilityRecordEnvelopeDigest",
        "toolchainClosureEnvelopeDigest",
        "releaseTimeRevocationCheckpointEnvelopeDigest",
        "predecessorDigest",
        "authorizedRollbackEnvelopeDigest",
        "b0RootEnvelopeDigest",
        "b3ProfileEnvelopeDigest",
    ] {
        digest_field(value, key)?;
    }
    sorted_digests(field(value, "provisionerArtifactDigests")?, 32)?;
    sorted_digests(field(value, "provenanceEnvelopeDigests")?, 32)?;
    if digest_field(value, "nativeClosureBaseDigest")? != native_closure_base_digest(value)? {
        return Err(ProtocolError("native closure base digest mismatch"));
    }
    for key in ["targetTriple", "variant", "buildId"] {
        id_field(value, key)?;
    }
    for key in [
        "artifactVersion",
        "releaseKeyEpoch",
        "timestampKeyEpoch",
        "releaseTimeRevocationSequence",
        "deploymentEpoch",
        "minimumArtifactVersion",
    ] {
        uint_field(value, key)?;
    }
    Ok(())
}
fn validate_index(value: &Value) -> Result<(), ProtocolError> {
    for key in [
        "a4ReleaseBaseDigest",
        "deploymentEnvelopeDigest",
        "nativeClosureEnvelopeDigest",
        "b0RootEnvelopeDigest",
    ] {
        digest_field(value, key)?;
    }
    uint_field(value, "releaseKeyEpoch")?;
    Ok(())
}
fn validate_revocation(value: &Value) -> Result<(), ProtocolError> {
    for key in ["authorityId", "namespace", "scope", "compromiseSemantics"] {
        id_field(value, key)?;
    }
    for key in ["keyEpoch", "sequence", "issuedCounter", "expiresCounter"] {
        uint_field(value, key)?;
    }
    if uint_field(value, "expiresCounter")? <= uint_field(value, "issuedCounter")? {
        return Err(ProtocolError("revocation counter order invalid"));
    }
    digest_field(value, "previousEnvelopeDigest")?;
    sorted_ids(field(value, "revokedKeys")?, 256)?;
    sorted_digests(field(value, "revokedArtifacts")?, 256)?;
    let cutoffs = array(field(value, "rotationCutoffs")?, 256)?;
    let mut prior = None;
    for cutoff in cutoffs {
        exact_keys(cutoff, &["keyId", "minimumEpoch"])?;
        let key = id_field(cutoff, "keyId")?;
        if prior.is_some_and(|previous| previous >= key) {
            return Err(ProtocolError("rotation cutoffs not sorted unique"));
        }
        prior = Some(key);
        uint_field(cutoff, "minimumEpoch")?;
    }
    Ok(())
}
fn validate_evidence(value: &Value, trust: TrustClass) -> Result<(), ProtocolError> {
    for key in [
        "deploymentId",
        "bootId",
        "kernelBootId",
        "helperBuildId",
        "requestId",
        "requestNonce",
        "challengeNonce",
        "proberId",
        "proberPrincipal",
    ] {
        id_field(value, key)?;
    }
    for key in [
        "deploymentEpoch",
        "requestSequence",
        "b3Counter",
        "capturedCounter",
        "expiresCounter",
        "proberKeyEpoch",
    ] {
        uint_field(value, key)?;
    }
    if uint_field(value, "expiresCounter")? < uint_field(value, "capturedCounter")?
        || uint_field(value, "capturedCounter")? < uint_field(value, "b3Counter")?
    {
        return Err(ProtocolError("evidence counter order invalid"));
    }
    for key in [
        "manifestDigest",
        "nativeClosureEnvelopeDigest",
        "helperArtifactDigest",
        "helperIncarnation",
        "protocolDigest",
        "requestDigest",
        "b3ProfileEnvelopeDigest",
        "b3LeaseReceiptEnvelopeDigest",
        "proberArtifactDigest",
        "proberIncarnation",
        "revocationEnvelopeDigest",
        "previousEvidenceDigest",
    ] {
        digest_field(value, key)?;
    }
    let roles = array(field(value, "roles")?, 32)?;
    let mut role_ids = std::collections::BTreeSet::new();
    let mut prior = None;
    for role in roles {
        exact_keys(
            role,
            &[
                "roleId",
                "roleClass",
                "principalId",
                "artifactDigest",
                "incarnationDigest",
                "uid",
                "gid",
                "groups",
                "namespaceInodes",
                "cgroupId",
            ],
        )?;
        let id = id_field(role, "roleId")?;
        if prior.is_some_and(|previous| previous >= id) || !role_ids.insert(id) {
            return Err(ProtocolError("evidence roles not sorted unique"));
        }
        prior = Some(id);
        enum_field(role, "roleClass", &["D1", "D2", "D3", "PROBER"])?;
        id_field(role, "principalId")?;
        digest_field(role, "artifactDigest")?;
        digest_field(role, "incarnationDigest")?;
        uint_field(role, "uid")?;
        uint_field(role, "gid")?;
        for group in array(field(role, "groups")?, 32)? {
            if group.as_u64().is_none() {
                return Err(ProtocolError("group malformed"));
            }
        }
        exact_uint_map(
            field(role, "namespaceInodes")?,
            &["user", "pid", "mount", "network", "ipc", "cgroup"],
        )?;
        id_field(role, "cgroupId")?;
    }
    let measurements = array(field(value, "measurements")?, 1024)?;
    let mut prior = None;
    let mut measurement_pairs = std::collections::BTreeSet::new();
    for measurement in measurements {
        exact_keys(
            measurement,
            &[
                "measurementId",
                "roleId",
                "field",
                "value",
                "mechanism",
                "mechanismVersion",
                "abi",
                "source",
                "transcriptDigest",
                "state",
                "reasonCode",
            ],
        )?;
        let id = id_field(measurement, "measurementId")?;
        if prior.is_some_and(|previous| previous >= id) {
            return Err(ProtocolError("measurements not sorted unique"));
        }
        prior = Some(id);
        if !role_ids.contains(id_field(measurement, "roleId")?) {
            return Err(ProtocolError("measurement role absent"));
        }
        let role = id_field(measurement, "roleId")?;
        let field_name = measurement_field(measurement, "field")?;
        if !measurement_pairs.insert((role, field_name)) {
            return Err(ProtocolError("measurement subject/field duplicate"));
        }
        for key in [
            "mechanism",
            "mechanismVersion",
            "abi",
            "source",
            "reasonCode",
        ] {
            id_field(measurement, key)?;
        }
        validate_measurement_value(field_name, field(measurement, "value")?)?;
        digest_field(measurement, "transcriptDigest")?;
        enum_field(
            measurement,
            "state",
            &["active", "inactive", "unsupported", "inconclusive"],
        )?;
    }
    if roles.is_empty()
        || roles.iter().any(|role| {
            MEASUREMENT_FIELDS.iter().any(|field_name| {
                !measurement_pairs.contains(&(id_field(role, "roleId").unwrap_or(""), *field_name))
            })
        })
    {
        return Err(ProtocolError("measurement registry coverage incomplete"));
    }
    let measured: std::collections::BTreeMap<(&str, &str), &Value> = measurements
        .iter()
        .map(|row| {
            Ok((
                (id_field(row, "roleId")?, measurement_field(row, "field")?),
                field(row, "value")?,
            ))
        })
        .collect::<Result<_, ProtocolError>>()?;
    for role in roles {
        let role_id = id_field(role, "roleId")?;
        let value = |name| {
            measured
                .get(&(role_id, name))
                .copied()
                .ok_or(ProtocolError("measurement missing"))
        };
        for name in [
            "identity.uid.real",
            "identity.uid.effective",
            "identity.uid.saved",
        ] {
            if uint_field(value(name)?, "value")? != uint_field(role, "uid")? {
                return Err(ProtocolError("UID evidence contradiction"));
            }
        }
        for name in [
            "identity.gid.real",
            "identity.gid.effective",
            "identity.gid.saved",
        ] {
            if uint_field(value(name)?, "value")? != uint_field(role, "gid")? {
                return Err(ProtocolError("GID evidence contradiction"));
            }
        }
        if field(value("identity.groups")?, "values")? != field(role, "groups")? {
            return Err(ProtocolError("group evidence contradiction"));
        }
        let namespace_value = value("namespaces.inodes")?;
        let namespace_role = field(role, "namespaceInodes")?;
        for key in ["user", "pid", "mount", "network", "ipc", "cgroup"] {
            if field(namespace_value, key)? != field(namespace_role, key)? {
                return Err(ProtocolError("namespace evidence contradiction"));
            }
        }
        if digest_field(value("incarnation")?, "pidfdDigest")?
            != digest_field(role, "incarnationDigest")?
        {
            return Err(ProtocolError("incarnation evidence contradiction"));
        }
        if digest_field(value("loader.executable")?, "value")?
            != digest_field(role, "artifactDigest")?
        {
            return Err(ProtocolError("executable evidence contradiction"));
        }
    }
    let probes = array(field(value, "negativeProbes")?, 256)?;
    let mut prior = None;
    for probe in probes {
        exact_keys(
            probe,
            &[
                "probeId",
                "roleId",
                "target",
                "action",
                "expectedField",
                "observedDenial",
                "errno",
                "signal",
                "controlDigest",
            ],
        )?;
        let id = id_field(probe, "probeId")?;
        if prior.is_some_and(|previous| previous >= id) {
            return Err(ProtocolError("negative probes not sorted unique"));
        }
        prior = Some(id);
        if !role_ids.contains(id_field(probe, "roleId")?) {
            return Err(ProtocolError("probe role absent"));
        }
        for key in ["target", "action", "errno", "signal"] {
            id_field(probe, key)?;
        }
        measurement_field(probe, "expectedField")?;
        bool_field(probe, "observedDenial")?;
        digest_field(probe, "controlDigest")?;
    }
    let fds = array(field(value, "inheritedFdInventory")?, 256)?;
    let mut fd_keys = std::collections::BTreeSet::new();
    for fd in fds {
        exact_keys(
            fd,
            &[
                "roleId",
                "slot",
                "purpose",
                "flagsDigest",
                "peerPrincipalId",
            ],
        )?;
        let role = id_field(fd, "roleId")?;
        if !role_ids.contains(role) || !fd_keys.insert((role, uint_field(fd, "slot")?)) {
            return Err(ProtocolError("fd inventory invalid or duplicate"));
        }
        id_field(fd, "purpose")?;
        digest_field(fd, "flagsDigest")?;
        id_field(fd, "peerPrincipalId")?;
    }
    let cleanup = field(value, "cleanup")?;
    exact_keys(
        cleanup,
        &[
            "state",
            "killedRoleIds",
            "reapedRoleIds",
            "closedFdCount",
            "revokedCredentialDomains",
            "journalDigest",
            "recoveryRequired",
        ],
    )?;
    enum_field(cleanup, "state", &["not-required", "complete", "failed"])?;
    sorted_ids(field(cleanup, "killedRoleIds")?, 32)?;
    sorted_ids(field(cleanup, "reapedRoleIds")?, 32)?;
    uint_field(cleanup, "closedFdCount")?;
    sorted_ids(field(cleanup, "revokedCredentialDomains")?, 32)?;
    digest_field(cleanup, "journalDigest")?;
    bool_field(cleanup, "recoveryRequired")?;
    let signature = field(value, "signature")?;
    exact_keys(signature, &["keyId", "algorithm", "keyEpoch", "signature"])?;
    require_key_namespace(id_field(signature, "keyId")?, trust)?;
    require_text(signature, "algorithm", "ed25519")?;
    if uint_field(signature, "keyEpoch")? != uint_field(value, "proberKeyEpoch")? {
        return Err(ProtocolError("evidence signature/prober epoch mismatch"));
    }
    signature_bytes(field(signature, "signature")?)?;
    Ok(())
}

pub fn classify(value: &Value) -> Result<Schema, ProtocolError> {
    if value.field("protocol").and_then(Value::as_text) == Some(PROTOCOL_NAME) {
        require_version(value, PROTOCOL_VERSION)?;
        if value.field("kind").is_some() {
            return Ok(Schema::Request);
        }
        if value.field("status").is_some() {
            return Ok(Schema::Response);
        }
        return Err(ProtocolError("wire kind is missing"));
    }
    let discriminator = value.field("schema").and_then(Value::as_text).or_else(|| {
        value
            .field("payload")
            .and_then(|payload| payload.field("schema"))
            .and_then(Value::as_text)
    });
    match discriminator {
        Some("keep.native-deployment") => Ok(Schema::Deployment),
        Some("keep.native-release-closure") => Ok(Schema::NativeClosure),
        Some("keep.native-release-index") => Ok(Schema::NativeIndex),
        Some("keep.native-evidence") => Ok(Schema::Evidence),
        Some("keep.native-revocation") => Ok(Schema::Revocation),
        _ => Err(ProtocolError("unknown schema")),
    }
}

pub fn validate_for(value: &Value, trust: TrustClass) -> Result<Schema, ProtocolError> {
    let schema = classify(value)?;
    match schema {
        Schema::Request => {
            let common = [
                "protocol",
                "version",
                "kind",
                "requestId",
                "deploymentId",
                "bootId",
                "manifestDigest",
                "nonce",
                "sequence",
                "deadlineMs",
            ];
            match value.field("kind").and_then(Value::as_text) {
                Some("launch") => {
                    let mut keys = common.to_vec();
                    keys.push("roles");
                    exact_keys(value, &keys)?;
                    let roles = array(
                        value.field("roles").ok_or(ProtocolError("roles missing"))?,
                        32,
                    )?;
                    if roles.is_empty() {
                        return Err(ProtocolError("roles empty"));
                    }
                    let mut role_ids = std::collections::BTreeSet::new();
                    let mut principals = std::collections::BTreeSet::new();
                    for role in roles {
                        exact_keys(
                            role,
                            &[
                                "roleId",
                                "roleClass",
                                "principalId",
                                "artifactDigest",
                                "credentialDomains",
                                "allowedChannelIds",
                            ],
                        )?;
                        if !role_ids.insert(identifier(
                            role.field("roleId")
                                .ok_or(ProtocolError("roleId missing"))?,
                        )?) || !principals.insert(identifier(
                            role.field("principalId")
                                .ok_or(ProtocolError("principal missing"))?,
                        )?) {
                            return Err(ProtocolError("roles duplicated"));
                        }
                        let class = role
                            .field("roleClass")
                            .and_then(Value::as_text)
                            .ok_or(ProtocolError("role class missing"))?;
                        if !matches!(class, "D1" | "D2" | "D3" | "PROBER") {
                            return Err(ProtocolError("role class unsupported"));
                        }
                        digest(
                            role.field("artifactDigest")
                                .ok_or(ProtocolError("artifact digest missing"))?,
                        )?;
                        let credentials = array(
                            role.field("credentialDomains")
                                .ok_or(ProtocolError("credentials missing"))?,
                            1,
                        )?;
                        unique_text(credentials)?;
                        if class != "D3" && !credentials.is_empty() {
                            return Err(ProtocolError("credentials outside D3"));
                        }
                        let channels = array(
                            role.field("allowedChannelIds")
                                .ok_or(ProtocolError("channels missing"))?,
                            128,
                        )?;
                        unique_text(channels)?;
                    }
                }
                Some("probe") => {
                    let mut keys = common.to_vec();
                    keys.extend(["roleHandleIds", "challengeNonce"]);
                    exact_keys(value, &keys)?;
                    let handles = array(
                        value
                            .field("roleHandleIds")
                            .ok_or(ProtocolError("handles missing"))?,
                        32,
                    )?;
                    if handles.is_empty() {
                        return Err(ProtocolError("probe handles empty"));
                    }
                    unique_text(handles)?;
                    identifier(
                        value
                            .field("challengeNonce")
                            .ok_or(ProtocolError("challenge missing"))?,
                    )?;
                }
                Some("cancel") => {
                    let mut keys = common.to_vec();
                    keys.push("targetRequestId");
                    exact_keys(value, &keys)?;
                    identifier(
                        value
                            .field("targetRequestId")
                            .ok_or(ProtocolError("cancel target missing"))?,
                    )?;
                }
                _ => return Err(ProtocolError("request kind is unsupported")),
            }
            for key in ["requestId", "deploymentId", "bootId", "nonce"] {
                identifier(
                    value
                        .field(key)
                        .ok_or(ProtocolError("request identity missing"))?,
                )?;
            }
            digest(
                value
                    .field("manifestDigest")
                    .ok_or(ProtocolError("manifest digest missing"))?,
            )?;
            if value.field("sequence").and_then(Value::as_u64).is_none()
                || value.field("deadlineMs").and_then(Value::as_u64).is_none()
            {
                return Err(ProtocolError("request integer missing"));
            }
        }
        Schema::Response => {
            exact_keys(
                value,
                &[
                    "protocol",
                    "version",
                    "requestId",
                    "requestDigest",
                    "deploymentId",
                    "bootId",
                    "nonce",
                    "sequence",
                    "helperArtifactDigest",
                    "helperBuildId",
                    "kernelBootId",
                    "status",
                    "roleHandles",
                    "measurements",
                    "failureCode",
                    "evidenceBundleDigest",
                ],
            )?;
            let status = value
                .field("status")
                .and_then(Value::as_text)
                .ok_or(ProtocolError("response status malformed"))?;
            let handles = array(
                value
                    .field("roleHandles")
                    .ok_or(ProtocolError("response handles missing"))?,
                32,
            )?;
            let measurements = array(
                value
                    .field("measurements")
                    .ok_or(ProtocolError("response measurements missing"))?,
                1024,
            )?;
            let mut handle_ids = std::collections::BTreeSet::new();
            let mut role_ids = std::collections::BTreeSet::new();
            for handle in handles {
                exact_keys(
                    handle,
                    &[
                        "roleId",
                        "roleClass",
                        "handleId",
                        "incarnationDigest",
                        "artifactDigest",
                        "principalId",
                    ],
                )?;
                if !handle_ids.insert(identifier(
                    handle
                        .field("handleId")
                        .ok_or(ProtocolError("handle id missing"))?,
                )?) || !role_ids.insert(identifier(
                    handle
                        .field("roleId")
                        .ok_or(ProtocolError("role id missing"))?,
                )?) {
                    return Err(ProtocolError("response handles duplicated"));
                }
                identifier(
                    handle
                        .field("principalId")
                        .ok_or(ProtocolError("principal missing"))?,
                )?;
                digest(
                    handle
                        .field("incarnationDigest")
                        .ok_or(ProtocolError("incarnation digest missing"))?,
                )?;
                digest(
                    handle
                        .field("artifactDigest")
                        .ok_or(ProtocolError("artifact digest missing"))?,
                )?;
                if !matches!(
                    handle.field("roleClass").and_then(Value::as_text),
                    Some("D1" | "D2" | "D3" | "PROBER")
                ) {
                    return Err(ProtocolError("role class unsupported"));
                }
            }
            let mut measurement_ids = std::collections::BTreeSet::new();
            let mut measurement_pairs = std::collections::BTreeSet::new();
            for measurement in measurements {
                exact_keys(
                    measurement,
                    &[
                        "measurementId",
                        "roleHandleId",
                        "field",
                        "state",
                        "transcriptDigest",
                    ],
                )?;
                if !measurement_ids.insert(identifier(
                    measurement
                        .field("measurementId")
                        .ok_or(ProtocolError("measurement id missing"))?,
                )?) {
                    return Err(ProtocolError("measurements duplicated"));
                }
                let handle_id = identifier(
                    measurement
                        .field("roleHandleId")
                        .ok_or(ProtocolError("measurement handle missing"))?,
                )?;
                let field_name = measurement_field(measurement, "field")?;
                if !measurement_pairs.insert((handle_id, field_name)) {
                    return Err(ProtocolError(
                        "response measurement subject/field duplicate",
                    ));
                }
                digest(
                    measurement
                        .field("transcriptDigest")
                        .ok_or(ProtocolError("transcript digest missing"))?,
                )?;
                if !matches!(
                    measurement.field("state").and_then(Value::as_text),
                    Some("active" | "inactive" | "unsupported" | "inconclusive")
                ) {
                    return Err(ProtocolError("measurement state unsupported"));
                }
            }
            for key in [
                "requestId",
                "deploymentId",
                "bootId",
                "nonce",
                "helperBuildId",
                "kernelBootId",
            ] {
                identifier(
                    value
                        .field(key)
                        .ok_or(ProtocolError("response identity missing"))?,
                )?;
            }
            for key in ["requestDigest", "helperArtifactDigest"] {
                digest(
                    value
                        .field(key)
                        .ok_or(ProtocolError("response digest missing"))?,
                )?;
            }
            if value.field("sequence").and_then(Value::as_u64).is_none() {
                return Err(ProtocolError("response sequence missing"));
            }
            if let Some(bundle) = value.field("evidenceBundleDigest") {
                if !matches!(bundle, Value::Null) {
                    digest(bundle)?;
                }
            }
            match status {
                "ok" if matches!(value.field("evidenceBundleDigest"), Some(Value::Text(_)))
                    && value.field("failureCode").and_then(Value::as_text) == Some("") => {}
                "refused" | "failed" if handles.is_empty() && measurements.is_empty() => {
                    let code = identifier(
                        value
                            .field("failureCode")
                            .ok_or(ProtocolError("failure code missing"))?,
                    )?;
                    let is_null = matches!(value.field("evidenceBundleDigest"), Some(Value::Null));
                    let unavailable = code.starts_with("evidence.unavailable.");
                    if is_null != unavailable {
                        return Err(ProtocolError(
                            "failure evidence/code biconditional mismatch",
                        ));
                    }
                }
                _ => return Err(ProtocolError("response status/evidence mismatch")),
            }
        }
        Schema::Deployment => {
            let captured = payload(
                value,
                DEPLOYMENT_PAYLOAD_KEYS,
                "keep.native-deployment",
                Some(trust),
            )?;
            validate_deployment(captured)?;
            require_envelope_epoch(
                value,
                uint_field(field(captured, "release")?, "releaseKeyEpoch")?,
            )?;
        }
        Schema::NativeClosure => {
            let captured = payload(
                value,
                NATIVE_CLOSURE_PAYLOAD_KEYS,
                "keep.native-release-closure",
                Some(trust),
            )?;
            validate_closure(captured)?;
            require_envelope_epoch(value, uint_field(captured, "releaseKeyEpoch")?)?;
        }
        Schema::NativeIndex => {
            let captured = payload(
                value,
                NATIVE_INDEX_PAYLOAD_KEYS,
                "keep.native-release-index",
                Some(trust),
            )?;
            validate_index(captured)?;
            require_envelope_epoch(value, uint_field(captured, "releaseKeyEpoch")?)?;
        }
        Schema::Evidence => {
            exact_keys(value, EVIDENCE_KEYS)?;
            require_version(value, 1)?;
            require_text(value, "schema", "keep.native-evidence")?;
            validate_evidence(value, trust)?;
        }
        Schema::Revocation => {
            let captured = payload(
                value,
                &[
                    "schema",
                    "version",
                    "authorityId",
                    "namespace",
                    "scope",
                    "keyEpoch",
                    "sequence",
                    "previousEnvelopeDigest",
                    "issuedCounter",
                    "expiresCounter",
                    "revokedKeys",
                    "revokedArtifacts",
                    "rotationCutoffs",
                    "compromiseSemantics",
                ],
                "keep.native-revocation",
                None,
            )?;
            validate_envelope_key_namespaces(value, trust)?;
            validate_revocation(captured)?;
            require_envelope_epoch(value, uint_field(captured, "keyEpoch")?)?;
        }
    }
    Ok(schema)
}
pub fn validate(value: &Value) -> Result<Schema, ProtocolError> {
    validate_for(value, TrustClass::Development)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedDocument {
    schema: Schema,
    trust: TrustClass,
    canonical: Vec<u8>,
}
impl CapturedDocument {
    pub fn schema(&self) -> Schema {
        self.schema
    }
    pub fn trust(&self) -> TrustClass {
        self.trust
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}
pub fn capture_canonical(
    bytes: &[u8],
    limits: Limits,
    trust: TrustClass,
) -> Result<CapturedDocument, ProtocolError> {
    let value = decode_canonical(bytes, limits)?;
    let schema = validate_for(&value, trust)?;
    let canonical = encode_bounded(&value, limits)?;
    Ok(CapturedDocument {
        schema,
        trust,
        canonical,
    })
}

pub fn native_boundary_request_digest(value: &Value) -> Result<String, ProtocolError> {
    if validate_for(value, TrustClass::Development)? != Schema::Request {
        return Err(ProtocolError("native request digest received non-request"));
    }
    let canonical = encode_bounded(value, Limits::WIRE)?;
    let mut preimage = b"keep.eir.v1.keep.native-boundary-request/v2\0".to_vec();
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = u64::try_from(bytes.len())
        .ok()
        .and_then(|length| length.checked_mul(8))
        .expect("bounded SHA-256 input length");
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for block in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes(word.try_into().expect("four-byte chunk"));
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (index, value) in [a, b, c, d, e, f, g, hh].into_iter().enumerate() {
            h[index] = h[index].wrapping_add(value);
        }
    }
    let mut out = [0u8; 32];
    for (index, value) in h.into_iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    out
}

pub struct Sha256State {
    hash: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    byte_length: u64,
}

impl Default for Sha256State {
    fn default() -> Self {
        Self {
            hash: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            byte_length: 0,
        }
    }
}

impl Sha256State {
    pub fn new() -> Self {
        Self::default()
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(word.try_into().expect("four-byte chunk"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            self.hash[0],
            self.hash[1],
            self.hash[2],
            self.hash[3],
            self.hash[4],
            self.hash[5],
            self.hash[6],
            self.hash[7],
        );
        for index in 0..64 {
            let upper = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(upper)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let lower = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = lower.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (index, value) in [a, b, c, d, e, f, g, h].into_iter().enumerate() {
            self.hash[index] = self.hash[index].wrapping_add(value);
        }
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
        self.byte_length = self
            .byte_length
            .checked_add(u64::try_from(bytes.len()).expect("SHA-256 update length fits u64"))
            .expect("SHA-256 total length fits u64");
        if self.buffered != 0 {
            let take = (64 - self.buffered).min(bytes.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&bytes[..take]);
            self.buffered += take;
            bytes = &bytes[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            } else {
                return;
            }
        }
        while bytes.len() >= 64 {
            let block: &[u8; 64] = bytes[..64].try_into().expect("64-byte SHA-256 block");
            self.compress(block);
            bytes = &bytes[64..];
        }
        self.buffer[..bytes.len()].copy_from_slice(bytes);
        self.buffered = bytes.len();
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_length = self.byte_length.checked_mul(8).expect("SHA-256 bit length");
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
        } else {
            self.buffer[self.buffered..56].fill(0);
        }
        self.buffer[56..].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut output = [0u8; 32];
        for (index, value) in self.hash.into_iter().enumerate() {
            output[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn development_envelope(payload: Value) -> Value {
        Value::Map(vec![
            ("payload".into(), payload.clone()),
            (
                "payloadDigest".into(),
                Value::Text(sha256_hex(
                    &encode_bounded(&payload, Limits::MANIFEST).unwrap(),
                )),
            ),
            (
                "signatures".into(),
                Value::Array(vec![Value::Map(vec![
                    ("keyId".into(), Value::Text("development.release".into())),
                    ("algorithm".into(), Value::Text("ed25519".into())),
                    ("keyEpoch".into(), Value::Unsigned(7)),
                    ("signature".into(), Value::Bytes(vec![1; 64])),
                ])]),
            ),
        ])
    }

    fn native_closure_payload() -> Value {
        let digest = || Value::Text("ab".repeat(32));
        let mut fields = vec![
            (
                "schema".into(),
                Value::Text("keep.native-release-closure".into()),
            ),
            ("version".into(), Value::Unsigned(1)),
            ("trustClass".into(), Value::Text("development".into())),
        ];
        for key in [
            "a4ReleaseBaseDigest",
            "a4ArtifactInventoryDigest",
            "nativeArtifactInventoryDigest",
            "nativeDeploymentPayloadDigest",
            "nativeDeploymentEnvelopeDigest",
            "nativePackagePayloadDigest",
            "nativeClosureBaseDigest",
            "helperArtifactDigest",
            "trampolineArtifactDigest",
            "proberArtifactDigest",
            "protocolDigest",
            "evidenceSchemaDigest",
            "timestampRecordEnvelopeDigest",
            "sbomEnvelopeDigest",
            "reproducibilityRecordEnvelopeDigest",
            "toolchainClosureEnvelopeDigest",
            "releaseTimeRevocationCheckpointEnvelopeDigest",
            "predecessorDigest",
            "authorizedRollbackEnvelopeDigest",
            "b0RootEnvelopeDigest",
            "b3ProfileEnvelopeDigest",
        ] {
            fields.push((key.into(), digest()));
        }
        fields.push((
            "provisionerArtifactDigests".into(),
            Value::Array(vec![digest()]),
        ));
        fields.push((
            "provenanceEnvelopeDigests".into(),
            Value::Array(vec![digest()]),
        ));
        for key in ["targetTriple", "variant", "buildId"] {
            fields.push((key.into(), Value::Text(format!("test.{key}"))));
        }
        for key in [
            "artifactVersion",
            "releaseKeyEpoch",
            "timestampKeyEpoch",
            "releaseTimeRevocationSequence",
            "deploymentEpoch",
            "minimumArtifactVersion",
        ] {
            fields.push((key.into(), Value::Unsigned(7)));
        }
        let mut payload = Value::Map(fields);
        let base = native_closure_base_digest(&payload).unwrap();
        let Value::Map(fields) = &mut payload else {
            unreachable!();
        };
        fields
            .iter_mut()
            .find(|(key, _)| key == "nativeClosureBaseDigest")
            .unwrap()
            .1 = Value::Text(base);
        payload
    }

    fn exact_key_record(keys: &[&str]) -> Value {
        Value::Map(
            keys.iter()
                .map(|key| ((*key).to_owned(), Value::Null))
                .collect(),
        )
    }

    fn assert_legacy_and_mixed_keys_refused(keys: &[&str], old: &str, new: &str) {
        let current = exact_key_record(keys);
        assert!(exact_keys(&current, keys).is_ok());

        let mut legacy = current.clone();
        let Value::Map(fields) = &mut legacy else {
            unreachable!();
        };
        fields.retain(|(key, _)| key != new);
        fields.push((old.to_owned(), Value::Null));
        assert!(
            exact_keys(&legacy, keys).is_err(),
            "accepted legacy key {old}"
        );

        let mut mixed = current;
        let Value::Map(fields) = &mut mixed else {
            unreachable!();
        };
        fields.push((old.to_owned(), Value::Null));
        assert!(
            exact_keys(&mixed, keys).is_err(),
            "accepted mixed key {old}"
        );
    }

    #[test]
    fn qualified_digest_registry_is_exact_unique_closed_and_strictly_ranked() {
        let mut expected_paths = Vec::new();
        expected_paths.extend_from_slice(DEPLOYMENT_BASE_INPUTS);
        expected_paths.push("deployment.payload.rollback.authorizedRollbackEnvelopeDigest");
        expected_paths.push("deployment.payload.deploymentBaseDigest");
        expected_paths.extend_from_slice(CLOSURE_BASE_INPUTS);
        expected_paths.push("closure.payload.timestampRecordEnvelopeDigest");
        expected_paths.push("closure.payload.nativeClosureBaseDigest");
        expected_paths.extend_from_slice(OTHER_DIGEST_PATHS);

        let actual_paths: Vec<_> = NATIVE_V2_DIGEST_REGISTRY
            .iter()
            .map(|entry| entry.path)
            .collect();
        assert_eq!(actual_paths, expected_paths);
        assert_eq!(actual_paths.len(), 80);
        assert!(validate_digest_registry(&NATIVE_V2_DIGEST_REGISTRY).is_ok());

        let evidence_paths: Vec<_> = OTHER_DIGEST_PATHS
            .iter()
            .copied()
            .filter(|path| path.starts_with("evidence."))
            .collect();
        assert_eq!(evidence_paths, EVIDENCE_BUNDLE_INPUTS);

        let unique: std::collections::BTreeSet<_> = actual_paths.iter().copied().collect();
        assert_eq!(unique.len(), actual_paths.len());
        const NONZERO_RANKS: &[(&str, u8)] = &[
            ("revocation.payloadDigest", 1),
            ("deployment.payload.deploymentBaseDigest", 3),
            (
                "deployment.payload.rollback.authorizedRollbackEnvelopeDigest",
                4,
            ),
            ("closure.payload.authorizedRollbackEnvelopeDigest", 4),
            ("deployment.payloadDigest", 5),
            ("request.manifestDigest", 6),
            ("evidence.manifestDigest", 6),
            ("closure.payload.nativeDeploymentEnvelopeDigest", 6),
            ("index.payload.deploymentEnvelopeDigest", 6),
            ("closure.payload.nativeClosureBaseDigest", 7),
            ("closure.payload.timestampRecordEnvelopeDigest", 8),
            ("closure.payloadDigest", 9),
            ("index.payload.nativeClosureEnvelopeDigest", 10),
            ("evidence.nativeClosureEnvelopeDigest", 10),
            ("index.payloadDigest", 11),
            ("response.evidenceBundleDigest", 12),
        ];
        for entry in NATIVE_V2_DIGEST_REGISTRY.iter() {
            let expected_rank = NONZERO_RANKS
                .iter()
                .find(|(path, _)| *path == entry.path)
                .map_or(0, |(_, rank)| *rank);
            assert_eq!(entry.rank, expected_rank, "rank drift at {}", entry.path);
            let tail = entry.path.rsplit('.').next().unwrap();
            assert_eq!(entry.field, tail.strip_suffix("[]").unwrap_or(tail));
            if entry.path == "deployment.payload.deploymentBaseDigest" {
                assert_eq!(entry.semantic_type, "native-deployment-base-v1");
            } else if entry.path == "closure.payload.nativeClosureBaseDigest" {
                assert_eq!(entry.semantic_type, "native-release-closure-base-v1");
            } else if entry.path == "deployment.payloadDigest" {
                assert_eq!(entry.semantic_type, "native-deployment-payload-v1");
            } else if entry.path == "closure.payloadDigest" {
                assert_eq!(entry.semantic_type, "native-release-closure-payload-v1");
            } else if entry.path == "index.payloadDigest" {
                assert_eq!(entry.semantic_type, "native-release-index-payload-v1");
            } else if entry.path == "response.evidenceBundleDigest" {
                assert_eq!(entry.semantic_type, "native-evidence-bundle-v1");
            } else if entry.path == "revocation.payloadDigest" {
                assert_eq!(entry.semantic_type, "native-revocation-payload-v1");
            } else if matches!(
                entry.path,
                "request.manifestDigest" | "evidence.manifestDigest"
            ) || entry.path.ends_with("deploymentEnvelopeDigest")
                || entry.path.ends_with("nativeDeploymentEnvelopeDigest")
            {
                assert_eq!(entry.semantic_type, "native-deployment-envelope-v1");
            } else if entry.path.ends_with("nativeClosureEnvelopeDigest") {
                assert_eq!(entry.semantic_type, "native-release-closure-envelope-v1");
            } else {
                assert_eq!(entry.semantic_type, entry.path);
            }
        }

        let mut reverse_edge = NATIVE_V2_DIGEST_REGISTRY.to_vec();
        reverse_edge
            .iter_mut()
            .find(|entry| entry.path == "deployment.payload.deploymentBaseDigest")
            .unwrap()
            .depends_on = &["closure.payload.nativeClosureBaseDigest"];
        assert!(validate_digest_registry(&reverse_edge).is_err());

        let mut missing_dependency = NATIVE_V2_DIGEST_REGISTRY.to_vec();
        missing_dependency
            .iter_mut()
            .find(|entry| entry.path == "deployment.payload.deploymentBaseDigest")
            .unwrap()
            .depends_on = &["missing.payload.unknownDigest"];
        assert!(validate_digest_registry(&missing_dependency).is_err());

        let mut duplicate = NATIVE_V2_DIGEST_REGISTRY.to_vec();
        duplicate.push(NATIVE_V2_DIGEST_REGISTRY[0].clone());
        assert!(validate_digest_registry(&duplicate).is_err());

        let mut removed_required_edge = NATIVE_V2_DIGEST_REGISTRY.to_vec();
        removed_required_edge
            .iter_mut()
            .find(|entry| entry.path == "deployment.payloadDigest")
            .unwrap()
            .depends_on = DEPLOYMENT_BASE_INPUTS;
        assert!(validate_digest_registry(&removed_required_edge).is_err());

        let mut lowered_rank = NATIVE_V2_DIGEST_REGISTRY.to_vec();
        lowered_rank
            .iter_mut()
            .find(|entry| entry.path == "deployment.payloadDigest")
            .unwrap()
            .rank = 4;
        assert!(validate_digest_registry(&lowered_rank).is_err());

        let mut missing_required_node = NATIVE_V2_DIGEST_REGISTRY.to_vec();
        missing_required_node.retain(|entry| entry.path != "response.evidenceBundleDigest");
        assert!(validate_digest_registry(&missing_required_node).is_err());

        let mut omitted_typed_evidence = NATIVE_V2_DIGEST_REGISTRY.to_vec();
        omitted_typed_evidence
            .iter_mut()
            .find(|entry| entry.path == "response.evidenceBundleDigest")
            .unwrap()
            .depends_on = &[
            "evidence.manifestDigest",
            "evidence.nativeClosureEnvelopeDigest",
            "evidence.b3LeaseReceiptEnvelopeDigest",
            "evidence.revocationEnvelopeDigest",
            "evidence.previousEvidenceDigest",
        ];
        assert!(validate_digest_registry(&omitted_typed_evidence).is_err());

        let mut omitted_revoked_artifacts = NATIVE_V2_DIGEST_REGISTRY.to_vec();
        omitted_revoked_artifacts
            .iter_mut()
            .find(|entry| entry.path == "revocation.payloadDigest")
            .unwrap()
            .depends_on = &["revocation.payload.previousEnvelopeDigest"];
        assert!(validate_digest_registry(&omitted_revoked_artifacts).is_err());
    }

    #[test]
    fn migrated_deployment_index_and_evidence_keys_refuse_legacy_and_mixed_records() {
        let mut missing_deployment_base = exact_key_record(DEPLOYMENT_PAYLOAD_KEYS);
        let Value::Map(fields) = &mut missing_deployment_base else {
            unreachable!();
        };
        fields.retain(|(key, _)| key != "deploymentBaseDigest");
        assert!(exact_keys(&missing_deployment_base, DEPLOYMENT_PAYLOAD_KEYS).is_err());

        for (keys, migrations) in [
            (
                DEPLOYMENT_B3_KEYS,
                &[("genesisDigest", "genesisBaseDigest")][..],
            ),
            (
                DEPLOYMENT_REVOCATION_KEYS,
                &[("genesisCheckpointDigest", "genesisCheckpointEnvelopeDigest")][..],
            ),
            (
                DEPLOYMENT_ROLLBACK_KEYS,
                &[(
                    "authorizedRollbackDigest",
                    "authorizedRollbackEnvelopeDigest",
                )][..],
            ),
            (
                NATIVE_INDEX_PAYLOAD_KEYS,
                &[("b0RootDigest", "b0RootEnvelopeDigest")][..],
            ),
            (
                EVIDENCE_KEYS,
                &[
                    ("nativeClosureDigest", "nativeClosureEnvelopeDigest"),
                    ("b3AuthorityDigest", "b3ProfileEnvelopeDigest"),
                    ("revocationDigest", "revocationEnvelopeDigest"),
                ][..],
            ),
        ] {
            for (old, new) in migrations {
                assert_legacy_and_mixed_keys_refused(keys, old, new);
            }
        }

        let mut b3_without_profile = exact_key_record(DEPLOYMENT_B3_KEYS);
        let Value::Map(fields) = &mut b3_without_profile else {
            unreachable!();
        };
        fields.retain(|(key, _)| key != "b3ProfileEnvelopeDigest");
        assert!(exact_keys(&b3_without_profile, DEPLOYMENT_B3_KEYS).is_err());

        let evidence = exact_key_record(EVIDENCE_KEYS);
        assert!(evidence.field("b3LeaseReceiptEnvelopeDigest").is_some());
        let mut without_lease = evidence;
        let Value::Map(fields) = &mut without_lease else {
            unreachable!();
        };
        fields.retain(|(key, _)| key != "b3LeaseReceiptEnvelopeDigest");
        assert!(exact_keys(&without_lease, EVIDENCE_KEYS).is_err());
    }

    #[test]
    fn native_closure_accepts_only_migrated_digest_field_names() {
        let payload = native_closure_payload();
        assert_eq!(
            validate_for(
                &development_envelope(payload.clone()),
                TrustClass::Development,
            )
            .unwrap(),
            Schema::NativeClosure,
        );

        for (old, new) in [
            ("artifactInventoryDigest", "a4ArtifactInventoryDigest"),
            ("nativePackageDigest", "nativePackagePayloadDigest"),
            ("timestampRecordDigest", "timestampRecordEnvelopeDigest"),
            ("sbomDigest", "sbomEnvelopeDigest"),
            ("provenanceDigests", "provenanceEnvelopeDigests"),
            (
                "reproducibilityRecordDigest",
                "reproducibilityRecordEnvelopeDigest",
            ),
            ("toolchainClosureDigest", "toolchainClosureEnvelopeDigest"),
            (
                "releaseTimeRevocationCheckpointDigest",
                "releaseTimeRevocationCheckpointEnvelopeDigest",
            ),
            (
                "authorizedRollbackDigest",
                "authorizedRollbackEnvelopeDigest",
            ),
            ("b0RootDigest", "b0RootEnvelopeDigest"),
            ("b3AuthorityDigest", "b3ProfileEnvelopeDigest"),
        ] {
            let mut legacy = payload.clone();
            let Value::Map(fields) = &mut legacy else {
                unreachable!();
            };
            let (_, value) = fields.iter_mut().find(|(key, _)| key == new).unwrap();
            let value = value.clone();
            fields.retain(|(key, _)| key != new);
            fields.push((old.into(), value));
            assert!(
                validate_for(&development_envelope(legacy), TrustClass::Development).is_err(),
                "accepted legacy field {old}",
            );
        }

        let mut mixed = payload;
        let Value::Map(fields) = &mut mixed else {
            unreachable!();
        };
        fields.push(("nativePackageDigest".into(), Value::Text("ab".repeat(32))));
        assert!(validate_for(&development_envelope(mixed), TrustClass::Development).is_err());
    }

    #[test]
    fn deployment_base_projection_binds_included_fields_and_excludes_only_descendants() {
        let mut deployment = exact_key_record(DEPLOYMENT_PAYLOAD_KEYS);
        let Value::Map(fields) = &mut deployment else {
            unreachable!();
        };
        fields
            .iter_mut()
            .find(|(key, _)| key == "rollback")
            .unwrap()
            .1 = exact_key_record(DEPLOYMENT_ROLLBACK_KEYS);
        let base = deployment_base_digest(&deployment).unwrap();
        assert_eq!(
            base,
            "2f8a1de0473deeca969697f87eb336d39c018a3c6a411eecbb3f8ad15542ae1c"
        );

        let mut included = deployment.clone();
        let Value::Map(fields) = &mut included else {
            unreachable!();
        };
        fields
            .iter_mut()
            .find(|(key, _)| key == "deploymentId")
            .unwrap()
            .1 = Value::Text("changed.deployment".into());
        assert_ne!(deployment_base_digest(&included).unwrap(), base);

        for (container, field_name) in [
            (None, "deploymentBaseDigest"),
            (Some("rollback"), "authorizedRollbackEnvelopeDigest"),
        ] {
            let mut excluded = deployment.clone();
            let target = match container {
                None => &mut excluded,
                Some(parent) => {
                    let Value::Map(fields) = &mut excluded else {
                        unreachable!();
                    };
                    &mut fields.iter_mut().find(|(key, _)| key == parent).unwrap().1
                }
            };
            let Value::Map(fields) = target else {
                unreachable!();
            };
            fields
                .iter_mut()
                .find(|(key, _)| key == field_name)
                .unwrap()
                .1 = Value::Text("descendant.substitution".into());
            assert_eq!(deployment_base_digest(&excluded).unwrap(), base);
        }
    }

    #[test]
    fn native_closure_base_recomputation_refuses_substitution_and_has_exact_exclusions() {
        let payload = native_closure_payload();
        let base = native_closure_base_digest(&payload).unwrap();
        assert_eq!(
            base,
            "2456ba1f573cb1d939cf3500941de023ad97e6468b72e9e8813437454d0bb79a"
        );

        let mut included = payload.clone();
        let Value::Map(fields) = &mut included else {
            unreachable!();
        };
        fields
            .iter_mut()
            .find(|(key, _)| key == "buildId")
            .unwrap()
            .1 = Value::Text("test.changed-build".into());
        assert_ne!(native_closure_base_digest(&included).unwrap(), base);
        assert!(validate_for(&development_envelope(included), TrustClass::Development,).is_err());

        for excluded_name in ["nativeClosureBaseDigest", "timestampRecordEnvelopeDigest"] {
            let mut excluded = payload.clone();
            let Value::Map(fields) = &mut excluded else {
                unreachable!();
            };
            fields
                .iter_mut()
                .find(|(key, _)| key == excluded_name)
                .unwrap()
                .1 = Value::Text("cd".repeat(32));
            assert_eq!(native_closure_base_digest(&excluded).unwrap(), base);
            if excluded_name == "timestampRecordEnvelopeDigest" {
                assert_eq!(
                    validate_for(&development_envelope(excluded), TrustClass::Development,)
                        .unwrap(),
                    Schema::NativeClosure,
                );
            } else {
                assert!(
                    validate_for(&development_envelope(excluded), TrustClass::Development,)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn canonical_scalars_and_order() {
        let value = Value::Map(vec![
            ("aa".into(), Value::Unsigned(24)),
            ("b".into(), Value::Bool(true)),
        ]);
        let bytes = encode_bounded(&value, Limits::WIRE).unwrap();
        assert_eq!(
            decode_canonical(&bytes, Limits::WIRE).unwrap(),
            Value::Map(vec![
                ("b".into(), Value::Bool(true)),
                ("aa".into(), Value::Unsigned(24))
            ])
        );
    }
    #[test]
    fn hostile_cbor_refuses() {
        for bytes in [
            &[0x18, 0][..],
            &[0x9f, 0xff],
            &[0xc0, 0xf6],
            &[0xf9, 0, 0],
            &[0x61, 0xff],
            &[0xa2, 0x61, b'a', 0, 0x61, b'a', 1],
        ] {
            assert!(
                decode_canonical(bytes, Limits::WIRE).is_err(),
                "accepted {bytes:x?}"
            );
        }
    }
    #[test]
    fn native_text_profile_rejects_unicode_and_controls() {
        assert!(encode_bounded(&Value::Text("e\u{301}".into()), Limits::WIRE).is_err());
        assert!(encode_bounded(&Value::Text("é".into()), Limits::WIRE).is_err());
        assert!(encode_bounded(&Value::Text("\0".into()), Limits::WIRE).is_err());
        assert!(decode_canonical(&[0x63, b'e', 0xcc, 0x81], Limits::WIRE).is_err());
    }
    #[test]
    fn sha256_matches_fips_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        let bytes = (0..131_137)
            .map(|value| (value % 251) as u8)
            .collect::<Vec<_>>();
        for chunk_size in [1, 3, 55, 56, 63, 64, 65, 4096, 65_536] {
            let mut streaming = Sha256State::new();
            for chunk in bytes.chunks(chunk_size) {
                streaming.update(chunk);
            }
            assert_eq!(streaming.finalize(), sha256(&bytes));
        }
    }
    #[test]
    fn bounded_encoder_enforces_output_text_collection_item_and_depth_limits() {
        let tiny = Limits {
            max_bytes: 8,
            max_depth: 2,
            max_items: 8,
            max_collection_items: 2,
            max_text_bytes: 2,
        };
        assert!(encode_bounded(&Value::Bytes(vec![0; 7]), tiny).is_ok());
        assert!(encode_bounded(&Value::Bytes(vec![0; 8]), tiny).is_err());
        assert!(
            encode_bounded(
                &Value::Array(vec![Value::Bytes(vec![0; 6]), Value::Bytes(vec![0; 6])]),
                tiny
            )
            .is_err()
        );
        assert!(
            encode_bounded(
                &Value::Map(vec![("aa".into(), Value::Bytes(vec![0; 4]))]),
                tiny
            )
            .is_err()
        );
        assert!(encode_bounded(&Value::Text("aa".into()), tiny).is_ok());
        assert!(encode_bounded(&Value::Text("aaa".into()), tiny).is_err());
        assert!(encode_bounded(&Value::Array(vec![Value::Null, Value::Null]), tiny).is_ok());
        assert!(
            encode_bounded(
                &Value::Array(vec![Value::Null, Value::Null, Value::Null]),
                tiny
            )
            .is_err()
        );
        assert!(encode_bounded(&Value::Array(vec![Value::Array(vec![Value::Null])]), tiny).is_ok());
        assert!(
            encode_bounded(
                &Value::Array(vec![Value::Array(vec![Value::Array(vec![Value::Null])])]),
                tiny
            )
            .is_err()
        );
        let item_limited = Limits {
            max_bytes: 64,
            max_depth: 8,
            max_items: 2,
            max_collection_items: 8,
            max_text_bytes: 8,
        };
        assert!(encode_bounded(&Value::Array(vec![Value::Null]), item_limited).is_ok());
        assert!(
            encode_bounded(&Value::Array(vec![Value::Null, Value::Null]), item_limited).is_err()
        );
    }
    #[test]
    fn deterministic_property_roundtrips_stay_canonical_and_bounded() {
        let mut state = 0x9e3779b97f4a7c15u64;
        for index in 0..2048 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let value = match index % 6 {
                0 => Value::Unsigned(state),
                1 => Value::Bool(state & 1 == 1),
                2 => Value::Text(format!("case.{:016x}", state)),
                3 => Value::Bytes(state.to_be_bytes().to_vec()),
                4 => Value::Array(vec![Value::Unsigned(state & 0xffff), Value::Null]),
                _ => Value::Map(vec![
                    ("id".into(), Value::Unsigned(state)),
                    ("ok".into(), Value::Bool(true)),
                ]),
            };
            let bytes = encode_bounded(&value, Limits::WIRE).unwrap();
            assert_eq!(decode_canonical(&bytes, Limits::WIRE).unwrap(), value);
        }
    }
    #[test]
    fn production_validation_rejects_development_trust_before_signatures_matter() {
        let payload = Value::Map(vec![
            (
                "schema".into(),
                Value::Text("keep.native-release-index".into()),
            ),
            ("version".into(), Value::Unsigned(1)),
            ("a4ReleaseBaseDigest".into(), Value::Text("ab".repeat(32))),
            (
                "deploymentEnvelopeDigest".into(),
                Value::Text("ab".repeat(32)),
            ),
            (
                "nativeClosureEnvelopeDigest".into(),
                Value::Text("ab".repeat(32)),
            ),
            ("b0RootEnvelopeDigest".into(), Value::Text("ab".repeat(32))),
            ("releaseKeyEpoch".into(), Value::Unsigned(1)),
            ("trustClass".into(), Value::Text("development".into())),
        ]);
        let envelope = Value::Map(vec![
            ("payload".into(), payload.clone()),
            (
                "payloadDigest".into(),
                Value::Text(sha256_hex(
                    &encode_bounded(&payload, Limits::MANIFEST).unwrap(),
                )),
            ),
            (
                "signatures".into(),
                Value::Array(vec![Value::Map(vec![
                    ("keyId".into(), Value::Text("development.key".into())),
                    ("algorithm".into(), Value::Text("ed25519".into())),
                    ("keyEpoch".into(), Value::Unsigned(1)),
                    (
                        "signature".into(),
                        Value::Text("development.signature".into()),
                    ),
                ])]),
            ),
        ]);
        assert!(validate_for(&envelope, TrustClass::Production).is_err());
    }
}
