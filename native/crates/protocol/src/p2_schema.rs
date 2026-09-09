//! Dependency-free P2-S1 schema capture and preimage construction.
//!
//! This module is deliberately structural and non-authorizing. It does not verify signatures,
//! touch the filesystem, mutate B3 state, or construct a production trust brand.

#![forbid(unsafe_code)]

use super::{Limits, ProtocolError, Value, decode_canonical, encode_bounded, sha256_hex};
use std::collections::BTreeSet;

pub const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SIGNATURES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RSpec {
    Identifier {
        values: Option<&'static [&'static str]>,
    },
    Text {
        values: Option<&'static [&'static str]>,
        pattern: Option<&'static str>,
    },
    Uint {
        minimum: u64,
        maximum: u64,
    },
    Boolean,
    Digest(&'static str),
    Bytes {
        exact: Option<usize>,
        maximum: Option<usize>,
    },
    Nullable(&'static RSpec),
    OneOf(&'static [RSpec]),
    Record(&'static [RFieldSpec]),
    Array {
        item: &'static RSpec,
        minimum: usize,
        maximum: usize,
        sorted_scalar: bool,
        sort_by: &'static [&'static str],
        unique_by: &'static [&'static str],
    },
    Tagged {
        tag: &'static str,
        variants: &'static [VariantSpec],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RFieldSpec {
    pub name: &'static str,
    pub spec: RSpec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VariantSpec {
    pub name: &'static str,
    pub spec: RSpec,
}

include!("p2_schema_specs.rs");

pub fn recursive_schema_spec(name: &str) -> Option<&'static RSpec> {
    Some(match name {
        "B3CasOperationV1" => &B3_CAS_OPERATION_V1_SPEC,
        "B3GenesisOperationV1" => &B3_GENESIS_OPERATION_V1_SPEC,
        "B3InvalidationAckV1" => &B3_INVALIDATION_ACK_V1_SPEC,
        "B3InvalidationFrameV1" => &B3_INVALIDATION_FRAME_V1_SPEC,
        "B3LeaseOperationV1" => &B3_LEASE_OPERATION_V1_SPEC,
        "B3ReadOperationV1" => &B3_READ_OPERATION_V1_SPEC,
        "B3ReceiptV1" => &B3_RECEIPT_V1_SPEC,
        "B3StateV1" => &B3_STATE_V1_SPEC,
        "B3SubscribeOperationV1" => &B3_SUBSCRIBE_OPERATION_V1_SPEC,
        "NativeArtifactInventoryV1" => &NATIVE_ARTIFACT_INVENTORY_V1_SPEC,
        "NativeB3GenesisBaseV1" => &NATIVE_B3_GENESIS_BASE_V1_SPEC,
        "NativeB3ProfileV1" => &NATIVE_B3_PROFILE_V1_SPEC,
        "NativeBuildCommandV1" => &NATIVE_BUILD_COMMAND_V1_SPEC,
        "NativeBuildIdentityV1" => &NATIVE_BUILD_IDENTITY_V1_SPEC,
        "NativeComparisonV1" => &NATIVE_COMPARISON_V1_SPEC,
        "NativeControlPolicyV1" => &NATIVE_CONTROL_POLICY_V1_SPEC,
        "NativeControlV1" => &NATIVE_CONTROL_V1_SPEC,
        "NativeEnvironmentPolicyV1" => &NATIVE_ENVIRONMENT_POLICY_V1_SPEC,
        "NativeFdFlagsV1" => &NATIVE_FD_FLAGS_V1_SPEC,
        "NativeGenesisEpochV1" => &NATIVE_GENESIS_EPOCH_V1_SPEC,
        "NativeInvocationV1" => &NATIVE_INVOCATION_V1_SPEC,
        "NativeIoMaxV1" => &NATIVE_IO_MAX_V1_SPEC,
        "NativeJournalEntriesV1" => &NATIVE_JOURNAL_ENTRIES_V1_SPEC,
        "NativeJournalV1" => &NATIVE_JOURNAL_V1_SPEC,
        "NativeLandlockPolicyV1" => &NATIVE_LANDLOCK_POLICY_V1_SPEC,
        "NativeLandlockPolicyV2" => &NATIVE_LANDLOCK_POLICY_V2_SPEC,
        "NativeObservationResultV1" => &NATIVE_OBSERVATION_RESULT_V1_SPEC,
        "NativePackagePayloadV1" => &NATIVE_PACKAGE_PAYLOAD_V1_SPEC,
        "NativePeerPolicyV1" => &NATIVE_PEER_POLICY_V1_SPEC,
        "NativeProvenanceV1" => &NATIVE_PROVENANCE_V1_SPEC,
        "NativeReproducibilityRecordV1" => &NATIVE_REPRODUCIBILITY_RECORD_V1_SPEC,
        "NativeRevocationLocatorV1" => &NATIVE_REVOCATION_LOCATOR_V1_SPEC,
        "NativeRevocationRecoveryV1" => &NATIVE_REVOCATION_RECOVERY_V1_SPEC,
        "NativeRollbackAuthorizationV1" => &NATIVE_ROLLBACK_AUTHORIZATION_V1_SPEC,
        "NativeRootCeremonyRecordV1" => &NATIVE_ROOT_CEREMONY_RECORD_V1_SPEC,
        "NativeRootLocatorV1" => &NATIVE_ROOT_LOCATOR_V1_SPEC,
        "NativeRootV1" => &NATIVE_ROOT_V1_SPEC,
        "NativeSbomV1" => &NATIVE_SBOM_V1_SPEC,
        "NativeSeccompPolicyV1" => &NATIVE_SECCOMP_POLICY_V1_SPEC,
        "NativeTimestampV1" => &NATIVE_TIMESTAMP_V1_SPEC,
        "NativeToolchainClosureV1" => &NATIVE_TOOLCHAIN_CLOSURE_V1_SPEC,
        "NativeTranscriptV1" => &NATIVE_TRANSCRIPT_V1_SPEC,
        "NativeTransportIdentityV1" => &NATIVE_TRANSPORT_IDENTITY_V1_SPEC,
        _ => return None,
    })
}

fn optional_strings(values: Option<&[&str]>) -> Value {
    values.map_or(Value::Null, |values| {
        Value::Array(values.iter().map(|v| Value::Text((*v).into())).collect())
    })
}

fn describe_recursive(spec: &RSpec) -> Value {
    let map = |rows: Vec<(&str, Value)>| {
        Value::Map(rows.into_iter().map(|(k, v)| (k.into(), v)).collect())
    };
    match spec {
        RSpec::Identifier { values } => map(vec![
            ("kind", Value::Text("identifier".into())),
            ("enum", optional_strings(*values)),
        ]),
        RSpec::Text { values, pattern } => map(vec![
            ("kind", Value::Text("text".into())),
            ("enum", optional_strings(*values)),
            (
                "pattern",
                pattern.map_or(Value::Null, |p| Value::Text(p.into())),
            ),
        ]),
        RSpec::Uint { minimum, maximum } => map(vec![
            ("kind", Value::Text("uint".into())),
            ("min", Value::Unsigned(*minimum)),
            ("max", Value::Unsigned(*maximum)),
        ]),
        RSpec::Boolean => map(vec![("kind", Value::Text("bool".into()))]),
        RSpec::Digest(semantic) => map(vec![
            ("kind", Value::Text("digest".into())),
            ("semantic", Value::Text((*semantic).into())),
        ]),
        RSpec::Bytes { exact, maximum } => map(vec![
            ("kind", Value::Text("bytes".into())),
            (
                "exact",
                exact.map_or(Value::Null, |v| Value::Unsigned(v as u64)),
            ),
            (
                "max",
                maximum.map_or(Value::Null, |v| Value::Unsigned(v as u64)),
            ),
        ]),
        RSpec::Nullable(inner) => map(vec![
            ("kind", Value::Text("nullable".into())),
            ("inner", describe_recursive(inner)),
        ]),
        RSpec::OneOf(variants) => map(vec![
            ("kind", Value::Text("one-of".into())),
            (
                "variants",
                Value::Array(variants.iter().map(describe_recursive).collect()),
            ),
        ]),
        RSpec::Record(fields) => map(vec![
            ("kind", Value::Text("record".into())),
            (
                "fields",
                Value::Array(
                    fields
                        .iter()
                        .map(|field| {
                            map(vec![
                                ("name", Value::Text(field.name.into())),
                                ("spec", describe_recursive(&field.spec)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
        RSpec::Array {
            item,
            minimum,
            maximum,
            sorted_scalar,
            sort_by,
            unique_by,
        } => map(vec![
            ("kind", Value::Text("array".into())),
            ("item", describe_recursive(item)),
            ("min", Value::Unsigned(*minimum as u64)),
            ("max", Value::Unsigned(*maximum as u64)),
            ("sortedScalar", Value::Bool(*sorted_scalar)),
            ("sortBy", optional_strings(Some(*sort_by))),
            ("uniqueBy", optional_strings(Some(*unique_by))),
        ]),
        RSpec::Tagged { tag, variants } => map(vec![
            ("kind", Value::Text("tagged".into())),
            ("tag", Value::Text((*tag).into())),
            (
                "variants",
                Value::Array(
                    variants
                        .iter()
                        .map(|variant| {
                            map(vec![
                                ("name", Value::Text(variant.name.into())),
                                ("spec", describe_recursive(&variant.spec)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
    }
}

pub fn recursive_schema_metadata() -> Result<Vec<u8>, ProtocolError> {
    let mut schemas: Vec<_> = P2_SCHEMAS.iter().chain(B3_OPERATION_SCHEMAS).collect();
    schemas.sort_by_key(|schema| schema.name);
    let value = Value::Array(
        schemas
            .into_iter()
            .map(|schema| {
                Value::Map(vec![
                    ("name".into(), Value::Text(schema.name.into())),
                    (
                        "spec".into(),
                        describe_recursive(
                            recursive_schema_spec(schema.name)
                                .expect("closed recursive schema registry"),
                        ),
                    ),
                ])
            })
            .collect(),
    );
    encode_bounded(
        &value,
        Limits {
            max_bytes: 1024 * 1024,
            max_depth: 64,
            ..Limits::MANIFEST
        },
    )
}

macro_rules! digest_types {
    ($($name:ident),+ $(,)?) => {$ (
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);
        impl $name {
            pub fn parse(text: &str) -> Result<Self, ProtocolError> {
                Ok(Self(parse_digest(text)?))
            }
            pub const fn bytes(&self) -> &[u8; 32] { &self.0 }
            pub fn to_hex(self) -> String { hex(&self.0) }
        }
    )+};
}

digest_types!(
    RootEnvelopeDigest,
    DeploymentBaseDigest,
    DeploymentEnvelopeDigest,
    ReleaseClosureBaseDigest,
    ReleaseClosureEnvelopeDigest,
    ReleaseIndexEnvelopeDigest,
    RevocationEnvelopeDigest,
    RollbackAuthorizationEnvelopeDigest,
    RevocationRecoveryEnvelopeDigest,
    B3ProfileEnvelopeDigest,
    B3LeaseReceiptEnvelopeDigest,
    B3StateDigest,
    GenesisBaseDigest,
    ArtifactDigest,
    PackageMemberDigest,
    MaterialDigest,
    SubjectDigest,
    SbomChecksumDigest,
    IoMaxDigest,
    LandlockDigest,
    LaunchSeccompDigest,
    SteadySeccompDigest,
    TranscriptDigest,
    ControlDigest,
    JournalDigest,
    TransportIdentityDigest,
    InvocationDigest,
    EnvironmentPolicyDigest,
    ComparisonDigest,
    GenesisEpochDigest,
    GenesisCarrierDigest,
    RootPayloadDigest,
    B3ProfilePayloadDigest,
    B3OperationDigest,
    QuarantineDigest,
    NativeArtifactInventoryDigest,
    NativePackagePayloadDigest,
    ToolchainClosureEnvelopeDigest,
    ProvenanceEnvelopeDigest,
    SbomEnvelopeDigest,
    ReproducibilityEnvelopeDigest,
    BuildIdentityEnvelopeDigest,
    BuilderIdentityEnvelopeDigest,
    ComparerIdentityEnvelopeDigest,
    CompilerDigest,
    SysrootDigest,
    LinkerDigest,
    VendorDigest,
    ContainerDigest,
    SourceDigest,
    ToolchainLineageDigest,
    BuildToolDigest,
    JournalEntriesDigest,
    PeerPolicyDigest,
    BuildCommandDigest,
    DisagreementsDigest,
    ObservationResultDigest,
    ControlPolicyDigest,
    ArtifactFileDigest,
    ToolchainEntryDigest,
    InvocationInputArtifactDigest,
    JournalSubjectDigest,
    CallerAuthorizationEnvelopeDigest,
    GenesisRootEnvelopeDigest,
    OciBlobDigest,
    CeremonyRequestDigest,
    B3InvalidationAckDigest,
    ConsumedAuthorizationEnvelopeDigest,
    ComparedArtifactDigest,
);

fn parse_digest(text: &str) -> Result<[u8; 32], ProtocolError> {
    if text.len() != 64
        || text.bytes().all(|byte| byte == b'0')
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError("P2 digest malformed"));
    }
    let mut out = [0; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| ProtocolError("P2 digest malformed"))?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldSpec {
    pub name: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaShape {
    Unsigned,
    Envelope,
    RootEnvelope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaSpec {
    pub name: &'static str,
    pub schema: &'static str,
    pub shape: SchemaShape,
    pub fields: &'static [FieldSpec],
    pub signature_domain: Option<&'static [u8]>,
    pub maximum_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignaturePreimageSpec {
    pub schema_name: &'static str,
    pub domain: &'static [u8],
    pub output_bytes: usize,
}

pub fn signature_preimage_registry() -> Vec<SignaturePreimageSpec> {
    let mut rows = Vec::new();
    for schema in P2_SCHEMAS.iter().chain(B3_OPERATION_SCHEMAS) {
        if schema.name == "NativeRootV1" {
            rows.push(SignaturePreimageSpec {
                schema_name: "NativeRootV1.initial",
                domain: b"keep.native-root-genesis/v1\0",
                output_bytes: 64,
            });
            rows.push(SignaturePreimageSpec {
                schema_name: "NativeRootV1.successor",
                domain: b"keep.native-root-update/v1\0",
                output_bytes: 64,
            });
        } else if let Some(domain) = schema.signature_domain {
            rows.push(SignaturePreimageSpec {
                schema_name: schema.name,
                domain,
                output_bytes: 64,
            });
        }
    }
    rows.sort_by_key(|row| row.schema_name);
    rows
}

/// Normalized recursive subtype metadata. The compact grammar is stable and oracle-facing:
/// `record{}`, `array<T,min,max,sort,unique>`, `enum[]`, `nullable<>`, and `tag<>`.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestRegistryEntry {
    pub path: String,
    pub semantic_type: String,
    pub rank: u8,
    pub depends_on: Vec<String>,
}

/// Registry derived from explicit field types, including typed empty arrays. It never examines
/// field-name suffixes. DAG edges are intentionally supplied only by frozen producer metadata.
pub fn digest_registry() -> Vec<DigestRegistryEntry> {
    let mut out = Vec::new();
    for schema in P2_SCHEMAS.iter().chain(B3_OPERATION_SCHEMAS) {
        let mut root =
            recursive_schema_spec(schema.name).expect("closed recursive schema registry");
        if !matches!(schema.shape, SchemaShape::Unsigned) {
            let RSpec::Record(fields) = root else {
                unreachable!()
            };
            root = &fields
                .iter()
                .find(|field| field.name == "payload")
                .expect("envelope payload")
                .spec;
        }
        collect_digest_leaves(root, schema.name.to_owned(), &mut out);
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    const EDGES: &[(&str, &str)] = &[
        (
            "NativeProvenanceV1.nativePackagePayloadDigest",
            "NativePackagePayloadV1.nativeArtifactInventoryDigest",
        ),
        (
            "NativeReproducibilityRecordV1.nativePackagePayloadDigest",
            "NativePackagePayloadV1.nativeArtifactInventoryDigest",
        ),
        (
            "NativeProvenanceV1.toolchainClosureEnvelopeDigest",
            "NativeToolchainClosureV1.$envelopeDigest",
        ),
        (
            "NativeProvenanceV1.invocationDigest",
            "NativeInvocationV1.$contentDigest",
        ),
        (
            "NativeReproducibilityRecordV1.builderProvenanceEnvelopeDigests",
            "NativeProvenanceV1.$envelopeDigest",
        ),
        (
            "NativeReproducibilityRecordV1.comparisonDigest",
            "NativeComparisonV1.$contentDigest",
        ),
    ];
    for &(consumer, producer) in EDGES {
        if let Some(entry) = out.iter_mut().find(|entry| entry.path == consumer) {
            entry.depends_on.push(producer.into());
        }
    }
    for schema in P2_SCHEMAS.iter().chain(B3_OPERATION_SCHEMAS) {
        let prefix = format!("{}.", schema.name);
        let mut dependencies: Vec<String> = out
            .iter()
            .filter(|entry| entry.path.starts_with(&prefix))
            .map(|entry| entry.path.clone())
            .collect();
        dependencies.sort();
        let rank = dependencies
            .iter()
            .filter_map(|path| {
                out.iter()
                    .find(|entry| &entry.path == path)
                    .map(|entry| entry.rank)
            })
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let (path, semantic) = match schema.shape {
            SchemaShape::Unsigned => (
                format!("{}.$contentDigest", schema.name),
                format!("{}ContentDigest", schema.name),
            ),
            SchemaShape::Envelope | SchemaShape::RootEnvelope => (
                format!("{}.$payloadDigest", schema.name),
                format!("{}PayloadDigest", schema.name),
            ),
        };
        out.push(DigestRegistryEntry {
            path: path.clone(),
            semantic_type: semantic,
            rank,
            depends_on: dependencies,
        });
        if !matches!(schema.shape, SchemaShape::Unsigned) {
            out.push(DigestRegistryEntry {
                path: format!("{}.$envelopeDigest", schema.name),
                semantic_type: format!("{}EnvelopeDigest", schema.name),
                rank: rank.saturating_add(1),
                depends_on: vec![path.clone()],
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn collect_digest_leaves(spec: &RSpec, path: String, out: &mut Vec<DigestRegistryEntry>) {
    match spec {
        RSpec::Digest(semantic) => {
            let semantic = if path.ends_with("authorizationEnvelopeDigest") {
                if path.contains("B3State")
                    || path.contains("proposedB3State")
                    || path.contains("expectedB3State")
                {
                    "ConsumedAuthorizationEnvelopeDigest"
                } else {
                    "CallerAuthorizationEnvelopeDigest"
                }
            } else if path == "NativeProvenanceV1.subjects[].digest" {
                "SubjectDigest"
            } else {
                semantic
            };
            out.push(DigestRegistryEntry {
                rank: digest_path_rank(semantic, &path),
                path,
                semantic_type: semantic.into(),
                depends_on: Vec::new(),
            });
        }
        RSpec::Nullable(inner) => collect_digest_leaves(inner, path, out),
        RSpec::OneOf(variants) => {
            for variant in *variants {
                collect_digest_leaves(variant, path.clone(), out);
            }
        }
        RSpec::Record(fields) => {
            for field in *fields {
                collect_digest_leaves(&field.spec, format!("{path}.{}", field.name), out);
            }
        }
        RSpec::Array { item, .. } => collect_digest_leaves(
            item,
            if matches!(**item, RSpec::Digest(_)) {
                path
            } else {
                format!("{path}[]")
            },
            out,
        ),
        RSpec::Tagged { variants, .. } => {
            for variant in *variants {
                collect_digest_leaves(&variant.spec, path.clone(), out);
            }
        }
        _ => {}
    }
}

fn digest_path_rank(semantic: &str, path: &str) -> u8 {
    if path.ends_with("scopeKey.genesisRootDigest") {
        return 2;
    }
    if semantic == "ConsumedAuthorizationEnvelopeDigest" {
        return 4;
    }
    if semantic == "CallerAuthorizationEnvelopeDigest" {
        return 2;
    }
    if path.starts_with("NativeRevocationRecoveryV1.") {
        if path.ends_with("rootEnvelopeDigest") || path.ends_with("b3ProfileEnvelopeDigest") {
            return 2;
        }
        if path.ends_with("headEnvelopeDigest") || path.ends_with("quarantineDigest") {
            return 1;
        }
    }
    if path == "NativeReproducibilityRecordV1.toolchainClosureEnvelopeDigest" {
        return 3;
    }
    digest_rank(semantic)
}

/// One executable graph for the already-frozen P1 boundary plus every P2-S1 typed path.
pub fn combined_digest_registry() -> Vec<DigestRegistryEntry> {
    let mut entries: Vec<_> = super::NATIVE_V2_DIGEST_REGISTRY
        .iter()
        .map(|entry| DigestRegistryEntry {
            path: entry.path.into(),
            semantic_type: entry.semantic_type.into(),
            rank: entry.rank,
            depends_on: entry.depends_on.iter().map(|path| (*path).into()).collect(),
        })
        .collect();
    entries.extend(digest_registry());
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

pub fn validate_digest_registry(entries: &[DigestRegistryEntry]) -> Result<(), ProtocolError> {
    let paths: BTreeSet<_> = entries.iter().map(|entry| entry.path.as_str()).collect();
    if paths.len() != entries.len() {
        return Err(ProtocolError("P2 digest registry path duplicate"));
    }
    for entry in entries {
        for dependency in &entry.depends_on {
            let producer = entries
                .iter()
                .find(|candidate| &candidate.path == dependency)
                .ok_or(ProtocolError("P2 digest dependency missing"))?;
            if producer.rank >= entry.rank {
                return Err(ProtocolError("P2 digest dependency rank not lower"));
            }
        }
    }
    for schema in P2_SCHEMAS.iter().chain(B3_OPERATION_SCHEMAS) {
        let prefix = format!("{}.", schema.name);
        if !entries.iter().any(|entry| entry.path.starts_with(&prefix)) {
            continue;
        }
        let primary = match schema.shape {
            SchemaShape::Unsigned => "$contentDigest",
            SchemaShape::Envelope | SchemaShape::RootEnvelope => "$payloadDigest",
        };
        for suffix in std::iter::once(primary)
            .chain((!matches!(schema.shape, SchemaShape::Unsigned)).then_some("$envelopeDigest"))
        {
            if !entries
                .iter()
                .any(|entry| entry.path == format!("{}.{}", schema.name, suffix))
            {
                return Err(ProtocolError("P2 derived digest output missing"));
            }
        }
    }
    Ok(())
}

fn digest_rank(semantic: &str) -> u8 {
    match semantic {
        "DeploymentBaseDigest" => 3,
        "DeploymentEnvelopeDigest" => 5,
        "ReleaseClosureBaseDigest" => 6,
        "ReleaseClosureEnvelopeDigest" => 8,
        "ReleaseIndexEnvelopeDigest" => 9,
        "NativePackagePayloadDigest" => 2,
        "InvocationDigest" | "ComparisonDigest" => 2,
        "ToolchainClosureEnvelopeDigest" => 3,
        "ProvenanceEnvelopeDigest" => 6,
        "NativeArtifactInventoryDigest" => 1,
        _ => 0,
    }
}

macro_rules! f {
    ($name:literal, $kind:ident) => {
        FieldSpec { name: $name }
    };
    ($name:literal, $kind:ident, $arg:expr) => {
        FieldSpec { name: $name }
    };
    ($name:literal, $kind:ident, $arg:expr, $element:expr) => {
        FieldSpec { name: $name }
    };
}

const GENESIS_EPOCH: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("trustClass", id),
    f!("rootId", id),
    f!("rootKeys", array, 32, "RootKeyRow"),
    f!("rootThreshold", u64),
    f!("participantIds", array, 64, "Identifier"),
    f!("minimumParticipants", u64),
    f!("requiredOffline", bool),
    f!("requiredWitnesses", u64),
    f!("issuedCounter", u64),
    f!("nonce", bytes32),
];
const ROOT: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("trustClass", id),
    f!("rootId", id),
    f!("rootEpoch", u64),
    f!("genesisEpochDigest", digest, "GenesisEpochDigest"),
    f!(
        "predecessorRootEnvelopeDigest",
        nullable_digest,
        "RootEnvelopeDigest"
    ),
    f!("issuedCounter", u64),
    f!("threshold", map),
    f!("rootKeys", array, 32, "RootKeyRow"),
    f!("releaseKeys", array, 32, "ReleaseKeyRow"),
    f!("timestampKeys", array, 32, "TimestampKeyRow"),
    f!("revocationKeys", array, 32, "RevocationKeyRow"),
    f!("recoveryKeys", array, 32, "RecoveryKeyRow"),
    f!("b3Keys", array, 32, "B3KeyRow"),
    f!("builderKeys", array, 32, "BuilderKeyRow"),
    f!("comparerKeys", array, 32, "ComparerKeyRow"),
    f!("keyEpochs", array, 8, "KeyEpochRow"),
];
const CEREMONY: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("trustClass", id),
    f!("ceremonyId", id),
    f!("rootEnvelopeDigest", digest, "RootEnvelopeDigest"),
    f!("genesisCarrierDigest", digest, "GenesisCarrierDigest"),
    f!("participantKeyIds", array, 64, "Identifier"),
    f!("requestDigest", digest, "CeremonyRequestDigest"),
    f!("transcriptDigest", digest, "TranscriptDigest"),
    f!("issuedCounter", u64),
];
const TIMESTAMP: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("trustClass", id),
    f!(
        "nativeClosureBaseDigest",
        digest,
        "ReleaseClosureBaseDigest"
    ),
    f!("artifactVersion", u64),
    f!("deploymentEpoch", u64),
    f!("releaseKeyEpoch", u64),
    f!("timestampKeyEpoch", u64),
    f!("issuedCounter", u64),
    f!("expiresCounter", u64),
    f!(
        "revocationCheckpointEnvelopeDigest",
        digest,
        "RevocationEnvelopeDigest"
    ),
    f!("revocationSequence", u64),
];
const ROLLBACK: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("trustClass", id),
    f!("authorizationId", id),
    f!(
        "fromDeploymentEnvelopeDigest",
        digest,
        "DeploymentEnvelopeDigest"
    ),
    f!("fromDeploymentEpoch", u64),
    f!("fromArtifactVersion", u64),
    f!("toDeploymentBaseDigest", digest, "DeploymentBaseDigest"),
    f!("toDeploymentEpoch", u64),
    f!("toArtifactVersion", u64),
    f!("minimumArtifactVersion", u64),
    f!(
        "predecessorDigest",
        digest,
        "RollbackAuthorizationEnvelopeDigest"
    ),
    f!("issuedCounter", u64),
    f!("expiresCounter", u64),
    f!("nonce", bytes32),
];
const RECOVERY: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("trustClass", id),
    f!("recoveryId", id),
    f!("authorityId", id),
    f!("namespace", id),
    f!("scope", id),
    f!("expectedB3State", map),
    f!("proposedB3StateProjection", map),
    f!(
        "quarantinedHeadEnvelopeDigests",
        array,
        4096,
        "RevocationEnvelopeDigest"
    ),
    f!(
        "selectedHeadEnvelopeDigest",
        digest,
        "RevocationEnvelopeDigest"
    ),
    f!("selectedSequence", u64),
    f!("issuedCounter", u64),
    f!("expiresCounter", u64),
    f!("reasonCode", id),
    f!("transcriptDigest", digest, "TranscriptDigest"),
];
const B3_GENESIS_BASE: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("trustClass", id),
    f!("authorityId", id),
    f!("namespace", id),
    f!("scope", id),
    f!("headSequence", u64),
    f!("headEnvelopeDigest", digest, "RevocationEnvelopeDigest"),
    f!("deploymentEpoch", u64),
    f!("artifactFloor", u64),
    f!("counter", u64),
];
const B3_PROFILE: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("trustClass", id),
    f!("authorityId", id),
    f!("b0RootEnvelopeDigest", digest, "RootEnvelopeDigest"),
    f!("genesisBaseDigest", digest, "GenesisBaseDigest"),
    f!(
        "predecessorProfileEnvelopeDigest",
        nullable_digest,
        "B3ProfileEnvelopeDigest"
    ),
    f!("algorithm", id),
    f!("keyId", id),
    f!("keyEpoch", u64),
    f!("publicKey", bytes32),
    f!("validFromCounter", u64),
    f!("validUntilCounter", u64),
    f!("transportIdentityDigest", digest, "TransportIdentityDigest"),
    f!("maxHeartbeatIntervalMs", u64),
];
const B3_STATE: &[FieldSpec] = &[
    f!("scopeKey", map),
    f!("generation", u64),
    f!("rootEpoch", u64),
    f!("rootEnvelopeDigest", digest, "RootEnvelopeDigest"),
    f!("b3ProfileEnvelopeDigest", digest, "B3ProfileEnvelopeDigest"),
    f!("headSequence", u64),
    f!("headEnvelopeDigest", digest, "RevocationEnvelopeDigest"),
    f!("deploymentEpoch", u64),
    f!("artifactFloor", u64),
    f!("counter", u64),
    f!("quarantined", bool),
    f!("quarantineDigest", digest, "QuarantineDigest"),
    f!("consumedAuthorization", nullable_map),
];
const B3_RECEIPT: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("operationKind", id),
    f!("authorityId", id),
    f!("b3ProfileEnvelopeDigest", digest, "B3ProfileEnvelopeDigest"),
    f!("scopeKey", map),
    f!("priorStateDigest", digest, "B3StateDigest"),
    f!("newStateDigest", digest, "B3StateDigest"),
    f!("operationDigest", digest, "B3OperationDigest"),
    f!("requestNonce", bytes32),
    f!("generation", u64),
    f!("counter", u64),
    f!("committed", bool),
    f!("keyId", id),
    f!("keyEpoch", u64),
];
const B3_FRAME: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("authorityId", id),
    f!("b3ProfileEnvelopeDigest", digest, "B3ProfileEnvelopeDigest"),
    f!("scopeKey", map),
    f!("sessionId", id),
    f!("frameKind", id),
    f!("sequence", u64),
    f!("priorGeneration", u64),
    f!("newGeneration", u64),
    f!("newStateDigest", digest, "B3StateDigest"),
    f!("counter", u64),
    f!("requestNonce", bytes32),
    f!("priorAckDigest", nullable_digest, "B3InvalidationAckDigest"),
];
const B3_ACK: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("sessionId", id),
    f!("sequence", u64),
    f!(
        "frameEnvelopeDigest",
        digest,
        "B3InvalidationFrameEnvelopeDigest"
    ),
    f!("requestNonce", bytes32),
];

const AUX_TRANSCRIPT: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("subjectDigest", digest, "SubjectDigest"),
    f!("mechanism", id),
    f!("mechanismVersion", id),
    f!("capturedCounter", u64),
    f!("resultDigest", digest, "ObservationResultDigest"),
];
const AUX_CONTROL: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("controlId", id),
    f!("subjectDigest", digest, "SubjectDigest"),
    f!("policyDigest", digest, "ControlPolicyDigest"),
];
const AUX_JOURNAL: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("deploymentId", id),
    f!("bootId", id),
    f!("sequence", u64),
    f!("previousJournalDigest", digest, "JournalDigest"),
    f!("entriesDigest", digest, "JournalEntriesDigest"),
];
const AUX_FD_FLAGS: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("flags", array, 256, "FdFlag"),
    f!("closeOnExec", bool),
    f!("seals", array, 256, "FdSeal"),
];
const AUX_TRANSPORT: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("transportKind", id),
    f!("endpointIdentity", id),
    f!("peerPolicyDigest", digest, "PeerPolicyDigest"),
];
const AUX_INVOCATION: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("buildId", id),
    f!("commandDigest", digest, "BuildCommandDigest"),
    f!("environmentPolicyDigest", digest, "EnvironmentPolicyDigest"),
    f!("inputs", array, 4096, "InvocationInput"),
];
const AUX_ENVIRONMENT: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("allowedVariables", array, 256, "Identifier"),
    f!("workingDirectoryPolicy", id),
    f!("networkPolicy", id),
];
const AUX_COMPARISON: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("algorithm", id),
    f!("leftSubjectDigest", digest, "SubjectDigest"),
    f!("rightSubjectDigest", digest, "SubjectDigest"),
    f!("disagreementsDigest", digest, "DisagreementsDigest"),
];
const OBSERVATION_RESULT: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("resultCode", id),
    f!("facts", array, 1024, "ObservationFact"),
];
const CONTROL_POLICY: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("controlId", id),
    f!("decisionClass", id),
    f!("requirements", array, 256, "ControlRequirement"),
];
const JOURNAL_ENTRIES: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("entries", array, 4096, "JournalEntry"),
];
const PEER_POLICY: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("requiredUid", nullable_u64),
    f!("requiredGid", nullable_u64),
    f!("requiredSecurityLabel", nullable_id),
];

const ARTIFACT_INVENTORY: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("buildId", id),
    f!("targetTriple", id),
    f!("variant", id),
    f!("rows", array, 256, "ArtifactInventoryRow"),
];
const PACKAGE_PAYLOAD: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("buildId", id),
    f!("targetTriple", id),
    f!("variant", id),
    f!(
        "nativeArtifactInventoryDigest",
        digest,
        "NativeArtifactInventoryDigest"
    ),
    f!("members", array, 4096, "PackageMemberRow"),
];
const TOOLCHAIN: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("toolchainId", id),
    f!("targetTriple", id),
    f!("variant", id),
    f!("compilerDigest", digest, "CompilerDigest"),
    f!("sysrootDigest", digest, "SysrootDigest"),
    f!("linkerDigest", digest, "LinkerDigest"),
    f!("vendorDigest", digest, "VendorDigest"),
    f!("containerDigest", digest, "ContainerDigest"),
    f!("environmentPolicyDigest", digest, "EnvironmentPolicyDigest"),
    f!("entries", array, 8192, "ToolchainEntry"),
];
const SBOM: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("buildId", id),
    f!("targetTriple", id),
    f!("variant", id),
    f!(
        "nativeArtifactInventoryDigest",
        digest,
        "NativeArtifactInventoryDigest"
    ),
    f!("packages", array, 4096, "SbomPackageRow"),
];
const PROVENANCE: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("builderId", id),
    f!(
        "builderIdentityEnvelopeDigest",
        digest,
        "BuilderIdentityEnvelopeDigest"
    ),
    f!("buildType", id),
    f!("buildId", id),
    f!("targetTriple", id),
    f!("variant", id),
    f!(
        "nativeArtifactInventoryDigest",
        digest,
        "NativeArtifactInventoryDigest"
    ),
    f!(
        "nativePackagePayloadDigest",
        digest,
        "NativePackagePayloadDigest"
    ),
    f!(
        "toolchainClosureEnvelopeDigest",
        digest,
        "ToolchainClosureEnvelopeDigest"
    ),
    f!("invocationDigest", digest, "InvocationDigest"),
    f!("materials", array, 8192, "ProvenanceMaterialRow"),
    f!("subjects", array, 4096, "ProvenanceSubjectRow"),
    f!("startedCounter", u64),
    f!("finishedCounter", u64),
];
const REPRO: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!(
        "comparerIdentityEnvelopeDigest",
        digest,
        "ComparerIdentityEnvelopeDigest"
    ),
    f!("buildId", id),
    f!("targetTriple", id),
    f!("variant", id),
    f!(
        "nativeArtifactInventoryDigest",
        digest,
        "NativeArtifactInventoryDigest"
    ),
    f!(
        "nativePackagePayloadDigest",
        digest,
        "NativePackagePayloadDigest"
    ),
    f!(
        "toolchainClosureEnvelopeDigest",
        digest,
        "ToolchainClosureEnvelopeDigest"
    ),
    f!(
        "builderProvenanceEnvelopeDigests",
        array,
        8,
        "ProvenanceEnvelopeDigest"
    ),
    f!("comparisonAlgorithm", id),
    f!("comparisonDigest", digest, "ComparisonDigest"),
    f!("disagreements", array, 1024, "DisagreementRow"),
];
const BUILD_IDENTITY: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("trustClass", id),
    f!("identityKind", id),
    f!("identityId", id),
    f!("administrativeDomain", id),
    f!("toolchainLineageDigest", digest, "ToolchainLineageDigest"),
    f!("keyId", id),
    f!("keyEpoch", u64),
    f!("publicKey", bytes32),
    f!("validFromCounter", u64),
    f!("validUntilCounter", u64),
];
const ROOT_LOCATOR: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("rootEpoch", u64),
    f!("rootEnvelopeDigest", digest, "RootEnvelopeDigest"),
];
const REVOCATION_LOCATOR: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("sequence", u64),
    f!(
        "revocationEnvelopeDigest",
        digest,
        "RevocationEnvelopeDigest"
    ),
];
const BUILD_COMMAND: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("executableDigest", digest, "BuildToolDigest"),
    f!("arguments", array, 256, "Text"),
];
const IO_MAX: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("defaultPolicy", id),
    f!("rows", array, 128, "IoMaxRow"),
];
const LANDLOCK: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("minimumAbi", u64),
    f!(
        "handledFilesystemRights",
        array,
        256,
        "LandlockFilesystemRight"
    ),
    f!("handledNetworkRights", array, 256, "LandlockNetworkRight"),
    f!("handledScopeRights", array, 256, "LandlockScopeRight"),
    f!("rules", array, 256, "LandlockRule"),
];
const LANDLOCK_V2: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("minimumAbi", u64),
    f!("effectiveAbi", u64),
    f!("reviewedMaximumAbi", u64),
    f!(
        "handledFilesystemRights",
        array,
        17,
        "LandlockFilesystemRightV2"
    ),
    f!("handledNetworkRights", array, 4, "LandlockNetworkRightV2"),
    f!("handledScopeRights", array, 2, "LandlockScopeRight"),
    f!("rules", array, 256, "LandlockRuleV2"),
];
const SECCOMP: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("architecture", id),
    f!("defaultAction", id),
    f!("rules", array, 512, "SeccompRule"),
];

macro_rules! schema {
    ($name:literal, $schema:literal, $shape:ident, $fields:ident, $domain:expr) => {
        SchemaSpec {
            name: $name,
            schema: $schema,
            shape: SchemaShape::$shape,
            fields: $fields,
            signature_domain: $domain,
            maximum_bytes: MAX_ENVELOPE_BYTES,
        }
    };
}

pub static P2_SCHEMAS: &[SchemaSpec] = &[
    schema!(
        "NativeBuildIdentityV1",
        "keep.native-build-identity",
        Envelope,
        BUILD_IDENTITY,
        Some(b"keep.native-build-identity/v1\0")
    ),
    schema!(
        "NativeArtifactInventoryV1",
        "keep.native-artifact-inventory",
        Unsigned,
        ARTIFACT_INVENTORY,
        None
    ),
    schema!(
        "NativePackagePayloadV1",
        "keep.native-package-payload",
        Unsigned,
        PACKAGE_PAYLOAD,
        None
    ),
    schema!(
        "NativeToolchainClosureV1",
        "keep.native-toolchain",
        Envelope,
        TOOLCHAIN,
        Some(b"keep.native-toolchain/v1\0")
    ),
    schema!(
        "NativeSbomV1",
        "keep.native-sbom",
        Envelope,
        SBOM,
        Some(b"keep.native-sbom/v1\0")
    ),
    schema!(
        "NativeProvenanceV1",
        "keep.native-provenance",
        Envelope,
        PROVENANCE,
        Some(b"keep.native-provenance/v1\0")
    ),
    schema!(
        "NativeReproducibilityRecordV1",
        "keep.native-repro",
        Envelope,
        REPRO,
        Some(b"keep.native-repro/v1\0")
    ),
    schema!(
        "NativeRootLocatorV1",
        "keep.native-root-locator",
        Unsigned,
        ROOT_LOCATOR,
        None
    ),
    schema!(
        "NativeRevocationLocatorV1",
        "keep.native-revocation-locator",
        Unsigned,
        REVOCATION_LOCATOR,
        None
    ),
    schema!(
        "NativeGenesisEpochV1",
        "keep.native-genesis-epoch",
        Unsigned,
        GENESIS_EPOCH,
        None
    ),
    schema!("NativeRootV1", "keep.native-root", RootEnvelope, ROOT, None),
    schema!(
        "NativeRootCeremonyRecordV1",
        "keep.native-root-ceremony",
        Envelope,
        CEREMONY,
        Some(b"keep.native-root-ceremony/v1\0")
    ),
    schema!(
        "NativeTimestampV1",
        "keep.native-timestamp",
        Envelope,
        TIMESTAMP,
        Some(b"keep.native-timestamp/v1\0")
    ),
    schema!(
        "NativeRollbackAuthorizationV1",
        "keep.native-rollback",
        Envelope,
        ROLLBACK,
        Some(b"keep.native-rollback/v1\0")
    ),
    schema!(
        "NativeRevocationRecoveryV1",
        "keep.native-revocation-recovery",
        Envelope,
        RECOVERY,
        Some(b"keep.native-revocation-recovery/v1\0")
    ),
    schema!(
        "NativeB3GenesisBaseV1",
        "keep.native-b3-genesis-base",
        Unsigned,
        B3_GENESIS_BASE,
        None
    ),
    schema!(
        "B3StateV1",
        "keep.native-b3-state",
        Unsigned,
        B3_STATE,
        None
    ),
    schema!(
        "NativeB3ProfileV1",
        "keep.native-b3-profile",
        Envelope,
        B3_PROFILE,
        Some(b"keep.native-b3-profile/v1\0")
    ),
    schema!(
        "B3ReceiptV1",
        "keep.native-b3-receipt",
        Envelope,
        B3_RECEIPT,
        Some(b"keep.native-b3-receipt/v1\0")
    ),
    schema!(
        "B3InvalidationFrameV1",
        "keep.native-b3-invalidation",
        Envelope,
        B3_FRAME,
        Some(b"keep.native-b3-invalidation/v1\0")
    ),
    schema!(
        "B3InvalidationAckV1",
        "keep.native-b3-invalidation-ack",
        Unsigned,
        B3_ACK,
        None
    ),
    schema!(
        "NativeTranscriptV1",
        "keep.native-transcript",
        Unsigned,
        AUX_TRANSCRIPT,
        None
    ),
    schema!(
        "NativeControlV1",
        "keep.native-control",
        Unsigned,
        AUX_CONTROL,
        None
    ),
    schema!(
        "NativeJournalV1",
        "keep.native-journal",
        Unsigned,
        AUX_JOURNAL,
        None
    ),
    schema!(
        "NativeFdFlagsV1",
        "keep.native-fd-flags",
        Unsigned,
        AUX_FD_FLAGS,
        None
    ),
    schema!(
        "NativeTransportIdentityV1",
        "keep.native-transport-identity",
        Unsigned,
        AUX_TRANSPORT,
        None
    ),
    schema!(
        "NativeInvocationV1",
        "keep.native-invocation",
        Unsigned,
        AUX_INVOCATION,
        None
    ),
    schema!(
        "NativeEnvironmentPolicyV1",
        "keep.native-environment-policy",
        Unsigned,
        AUX_ENVIRONMENT,
        None
    ),
    schema!(
        "NativeComparisonV1",
        "keep.native-comparison",
        Unsigned,
        AUX_COMPARISON,
        None
    ),
    schema!(
        "NativeObservationResultV1",
        "keep.native-observation-result",
        Unsigned,
        OBSERVATION_RESULT,
        None
    ),
    schema!(
        "NativeControlPolicyV1",
        "keep.native-control-policy",
        Unsigned,
        CONTROL_POLICY,
        None
    ),
    schema!(
        "NativeJournalEntriesV1",
        "keep.native-journal-entries",
        Unsigned,
        JOURNAL_ENTRIES,
        None
    ),
    schema!(
        "NativePeerPolicyV1",
        "keep.native-peer-policy",
        Unsigned,
        PEER_POLICY,
        None
    ),
    schema!(
        "NativeBuildCommandV1",
        "keep.native-build-command",
        Unsigned,
        BUILD_COMMAND,
        None
    ),
    schema!(
        "NativeIoMaxV1",
        "keep.native-io-max",
        Unsigned,
        IO_MAX,
        None
    ),
    schema!(
        "NativeLandlockPolicyV1",
        "keep.native-landlock-policy",
        Unsigned,
        LANDLOCK,
        None
    ),
    schema!(
        "NativeLandlockPolicyV2",
        "keep.native-landlock-policy",
        Unsigned,
        LANDLOCK_V2,
        None
    ),
    schema!(
        "NativeSeccompPolicyV1",
        "keep.native-seccomp-policy",
        Unsigned,
        SECCOMP,
        None
    ),
];

const SCOPE_KEYS: &[&str] = &["authorityId", "namespace", "scope", "genesisRootDigest"];
const OP_COMMON: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("operationKind", id),
];
const OP_GENESIS: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("operationKind", id),
    f!("genesisBaseDigest", digest, "GenesisBaseDigest"),
    f!("b0RootEnvelopeDigest", digest, "RootEnvelopeDigest"),
    f!("b3ProfileEnvelopeDigest", digest, "B3ProfileEnvelopeDigest"),
    f!("derivedGenesisStateDigest", digest, "B3StateDigest"),
    f!("requestNonce", bytes32),
];
const OP_READ: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("operationKind", id),
    f!("scopeKey", map),
    f!("requestNonce", bytes32),
];
const OP_CAS: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("operationKind", id),
    f!("scopeKey", map),
    f!("expectedStateDigest", digest, "B3StateDigest"),
    f!("newStateDigest", digest, "B3StateDigest"),
    f!("callerPurpose", map),
    f!("requestNonce", bytes32),
];
const OP_LEASE: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("operationKind", id),
    f!("scopeKey", map),
    f!("generation", u64),
    f!("headEnvelopeDigest", digest, "RevocationEnvelopeDigest"),
    f!("b3CounterCeiling", u64),
    f!("requestNonce", bytes32),
];
const OP_SUBSCRIBE: &[FieldSpec] = &[
    f!("schema", text),
    f!("version", u64),
    f!("operationKind", id),
    f!("scopeKey", map),
    f!("generation", u64),
    f!("sessionId", id),
    f!("requestNonce", bytes32),
];

pub static B3_OPERATION_SCHEMAS: &[SchemaSpec] = &[
    schema!(
        "B3GenesisOperationV1",
        "keep.native-b3-operation",
        Unsigned,
        OP_GENESIS,
        Some(b"keep.native-b3-genesis-operation/v1\0")
    ),
    schema!(
        "B3ReadOperationV1",
        "keep.native-b3-operation",
        Unsigned,
        OP_READ,
        Some(b"keep.native-b3-read/v1\0")
    ),
    schema!(
        "B3CasOperationV1",
        "keep.native-b3-operation",
        Unsigned,
        OP_CAS,
        Some(b"keep.native-b3-cas/v1\0")
    ),
    schema!(
        "B3LeaseOperationV1",
        "keep.native-b3-operation",
        Unsigned,
        OP_LEASE,
        Some(b"keep.native-b3-lease/v1\0")
    ),
    schema!(
        "B3SubscribeOperationV1",
        "keep.native-b3-operation",
        Unsigned,
        OP_SUBSCRIBE,
        Some(b"keep.native-b3-subscribe/v1\0")
    ),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2Capture {
    schema_name: &'static str,
    canonical: Vec<u8>,
    value: Value,
}

pub fn minimal_p2_corpus() -> Result<Vec<(&'static str, Vec<u8>)>, ProtocolError> {
    let mut corpus = Vec::new();
    for spec in P2_SCHEMAS.iter().chain(B3_OPERATION_SCHEMAS) {
        let recursive = recursive_schema_spec(spec.name).expect("closed recursive schema registry");
        let payload_spec = if matches!(spec.shape, SchemaShape::Unsigned) {
            recursive
        } else {
            let RSpec::Record(fields) = recursive else {
                unreachable!()
            };
            &fields
                .iter()
                .find(|field| field.name == "payload")
                .expect("payload field")
                .spec
        };
        let mut payload = minimal_recursive(payload_spec);
        specialize_minimal(spec, &mut payload)?;
        let value = match spec.shape {
            SchemaShape::Unsigned => payload,
            SchemaShape::Envelope | SchemaShape::RootEnvelope => {
                let digest = bare_digest(&payload, Limits::MANIFEST)?;
                let role_tagged = spec.shape == SchemaShape::RootEnvelope
                    && matches!(payload.field("rootEpoch"),Some(Value::Unsigned(epoch))if *epoch>0);
                Value::Map(vec![
                    ("payload".into(), payload),
                    ("payloadDigest".into(), Value::Text(digest)),
                    ("signatures".into(), minimal_signatures(role_tagged)),
                ])
            }
        };
        let bytes = encode_bounded(&value, Limits::MANIFEST)?;
        capture_p2(&bytes, Some(spec.name))?;
        corpus.push((spec.name, bytes));
    }
    corpus.sort_by_key(|row| row.0);
    Ok(corpus)
}
fn minimal_recursive(spec: &RSpec) -> Value {
    match spec {
        RSpec::Identifier { values } | RSpec::Text { values, .. } => Value::Text(
            values
                .and_then(|v| v.first())
                .copied()
                .unwrap_or("x")
                .into(),
        ),
        RSpec::Uint { minimum, .. } => Value::Unsigned(*minimum),
        RSpec::Boolean => Value::Bool(false),
        RSpec::Digest(_) => Value::Text("11".repeat(32)),
        RSpec::Bytes { exact, .. } => Value::Bytes(vec![0; exact.unwrap_or(0)]),
        RSpec::Nullable(_) => Value::Null,
        RSpec::OneOf(variants) => minimal_recursive(&variants[0]),
        RSpec::Record(fields) => Value::Map(
            fields
                .iter()
                .map(|field| (field.name.into(), minimal_recursive(&field.spec)))
                .collect(),
        ),
        RSpec::Array { item, minimum, .. } => {
            Value::Array((0..*minimum).map(|_| minimal_recursive(item)).collect())
        }
        RSpec::Tagged { variants, .. } => minimal_recursive(&variants[0].spec),
    }
}
fn set_value(value: &mut Value, name: &str, replacement: Value) {
    if let Value::Map(rows) = value {
        if let Some((_, slot)) = rows.iter_mut().find(|(key, _)| key == name) {
            *slot = replacement;
        }
    }
}
fn set_text(value: &mut Value, name: &str, text: &str) {
    set_value(value, name, Value::Text(text.into()));
}
fn set_uint(value: &mut Value, name: &str, n: u64) {
    set_value(value, name, Value::Unsigned(n));
}
fn minimal_scope() -> Value {
    Value::Map(vec![
        ("authorityId".into(), Value::Text("authority.1".into())),
        ("namespace".into(), Value::Text("native".into())),
        ("scope".into(), Value::Text("release".into())),
        ("genesisRootDigest".into(), Value::Text("11".repeat(32))),
    ])
}
fn minimal_key(id: &str) -> Value {
    Value::Map(vec![
        ("keyId".into(), Value::Text(id.into())),
        ("algorithm".into(), Value::Text("ed25519".into())),
        ("publicKey".into(), Value::Bytes(vec![1; 32])),
        ("keyEpoch".into(), Value::Unsigned(1)),
        ("validFromCounter".into(), Value::Unsigned(1)),
        ("validUntilCounter".into(), Value::Unsigned(2)),
    ])
}
fn minimal_signatures(role: bool) -> Value {
    let mut row = vec![
        ("keyId".into(), Value::Text("key.1".into())),
        ("algorithm".into(), Value::Text("ed25519".into())),
        ("keyEpoch".into(), Value::Unsigned(1)),
        ("signature".into(), Value::Bytes(vec![0; 64])),
    ];
    if role {
        row.push(("authorizationRole".into(), Value::Text("root".into())));
    }
    Value::Array(vec![Value::Map(row)])
}
fn minimal_state() -> Value {
    Value::Map(vec![
        ("scopeKey".into(), minimal_scope()),
        ("generation".into(), Value::Unsigned(0)),
        ("rootEpoch".into(), Value::Unsigned(0)),
        ("rootEnvelopeDigest".into(), Value::Text("11".repeat(32))),
        (
            "b3ProfileEnvelopeDigest".into(),
            Value::Text("11".repeat(32)),
        ),
        ("headSequence".into(), Value::Unsigned(0)),
        ("headEnvelopeDigest".into(), Value::Text("11".repeat(32))),
        ("deploymentEpoch".into(), Value::Unsigned(0)),
        ("artifactFloor".into(), Value::Unsigned(0)),
        ("counter".into(), Value::Unsigned(1)),
        ("quarantined".into(), Value::Bool(false)),
        ("quarantineDigest".into(), Value::Text("11".repeat(32))),
        ("consumedAuthorization".into(), Value::Null),
    ])
}
fn minimal_projection() -> Value {
    let Value::Map(mut rows) = minimal_state() else {
        unreachable!()
    };
    rows.retain(|(key, _)| key != "generation" && key != "consumedAuthorization");
    Value::Map(rows)
}
fn specialize_minimal(spec: &SchemaSpec, value: &mut Value) -> Result<(), ProtocolError> {
    match spec.name {
        "NativeGenesisEpochV1" => {
            set_text(value, "trustClass", "production");
            set_value(value, "rootKeys", Value::Array(vec![minimal_key("root.1")]));
            set_uint(value, "rootThreshold", 1);
            set_value(
                value,
                "participantIds",
                Value::Array(vec![Value::Text("participant.1".into())]),
            );
            set_uint(value, "minimumParticipants", 1);
        }
        "NativeRootV1" => {
            set_text(value, "trustClass", "production");
            set_text(value, "rootId", "root.1");
            let roles = [
                "root",
                "release",
                "timestamp",
                "revocation",
                "recovery",
                "b3",
                "builder",
                "comparer",
            ];
            set_value(
                value,
                "threshold",
                Value::Map(
                    [
                        "b3",
                        "builder",
                        "comparer",
                        "recovery",
                        "release",
                        "revocation",
                        "root",
                        "timestamp",
                    ]
                    .iter()
                    .map(|role| ((*role).into(), Value::Unsigned(1)))
                    .collect(),
                ),
            );
            for role in roles {
                set_value(
                    value,
                    &format!("{role}Keys"),
                    Value::Array(vec![minimal_key(&format!("{role}.1"))]),
                );
            }
            set_value(
                value,
                "keyEpochs",
                Value::Array(
                    [
                        "b3",
                        "builder",
                        "comparer",
                        "recovery",
                        "release",
                        "revocation",
                        "root",
                        "timestamp",
                    ]
                    .iter()
                    .map(|role| {
                        Value::Map(vec![
                            ("role".into(), Value::Text((*role).into())),
                            ("minimumEpoch".into(), Value::Unsigned(1)),
                        ])
                    })
                    .collect(),
                ),
            );
        }
        "NativeRootCeremonyRecordV1" => {
            set_text(value, "trustClass", "production");
            set_value(
                value,
                "participantKeyIds",
                Value::Array(vec![Value::Text("root.1".into())]),
            );
        }
        "NativeTimestampV1" => {
            set_text(value, "trustClass", "production");
            set_uint(value, "issuedCounter", 1);
            set_uint(value, "expiresCounter", 2);
        }
        "NativeRollbackAuthorizationV1" => {
            set_text(value, "trustClass", "production");
            set_uint(value, "fromDeploymentEpoch", 1);
            set_uint(value, "toDeploymentEpoch", 2);
            set_uint(value, "minimumArtifactVersion", 1);
            set_uint(value, "toArtifactVersion", 1);
            set_uint(value, "issuedCounter", 1);
            set_uint(value, "expiresCounter", 2);
        }
        "NativeRevocationRecoveryV1" => {
            set_text(value, "trustClass", "production");
            set_value(value, "expectedB3State", minimal_state());
            set_value(value, "proposedB3StateProjection", minimal_projection());
            set_value(
                value,
                "quarantinedHeadEnvelopeDigests",
                Value::Array(vec![Value::Text("11".repeat(32))]),
            );
            set_uint(value, "selectedSequence", 1);
            set_uint(value, "issuedCounter", 1);
            set_uint(value, "expiresCounter", 2);
        }
        "NativeB3GenesisBaseV1" => set_text(value, "trustClass", "production"),
        "B3StateV1" => *value = minimal_state(),
        "NativeB3ProfileV1" => {
            set_text(value, "trustClass", "production");
            set_text(value, "algorithm", "ed25519");
            set_uint(value, "validFromCounter", 1);
            set_uint(value, "validUntilCounter", 2);
            set_uint(value, "maxHeartbeatIntervalMs", 1);
        }
        "B3ReceiptV1" => {
            set_text(value, "operationKind", "read");
            set_value(value, "scopeKey", minimal_scope());
            set_value(value, "newStateDigest", Value::Text("11".repeat(32)));
            set_value(value, "priorStateDigest", Value::Text("11".repeat(32)));
        }
        "B3InvalidationFrameV1" => {
            set_value(value, "scopeKey", minimal_scope());
            set_text(value, "frameKind", "heartbeat");
            set_uint(value, "sequence", 1);
        }
        "B3InvalidationAckV1" => set_uint(value, "sequence", 1),
        "NativeBuildIdentityV1" => {
            set_text(value, "trustClass", "production");
            set_text(value, "identityKind", "builder");
            set_uint(value, "validFromCounter", 1);
            set_uint(value, "validUntilCounter", 2);
        }
        "NativeObservationResultV1" => set_text(value, "resultCode", "pass"),
        "NativeControlPolicyV1" => set_text(value, "decisionClass", "permit"),
        "NativePeerPolicyV1" => set_uint(value, "requiredUid", 0),
        "NativeFdFlagsV1" => {}
        "NativeTransportIdentityV1" => set_text(value, "transportKind", "vsock"),
        "NativeEnvironmentPolicyV1" => {
            set_text(value, "workingDirectoryPolicy", "empty");
            set_text(value, "networkPolicy", "denied");
        }
        "NativeComparisonV1" => {
            set_text(value, "algorithm", "sha256-byte-for-byte/v1");
            set_value(value, "rightSubjectDigest", Value::Text("22".repeat(32)));
        }
        "NativeIoMaxV1" => set_text(value, "defaultPolicy", "deny-unlisted"),
        "NativeLandlockPolicyV1" => set_uint(value, "minimumAbi", 1),
        "NativeLandlockPolicyV2" => {
            set_uint(value, "version", 2);
            set_uint(value, "minimumAbi", 4);
            set_uint(value, "effectiveAbi", 4);
            set_uint(value, "reviewedMaximumAbi", 10);
            set_value(
                value,
                "handledFilesystemRights",
                Value::Array(
                    LANDLOCK_V2_FS_ABI4
                        .iter()
                        .map(|right| Value::Text((*right).into()))
                        .collect(),
                ),
            );
            set_value(
                value,
                "handledNetworkRights",
                Value::Array(
                    LANDLOCK_V2_NET_ABI4_9
                        .iter()
                        .map(|right| Value::Text((*right).into()))
                        .collect(),
                ),
            );
            set_value(value, "handledScopeRights", Value::Array(vec![]));
        }
        "NativeSeccompPolicyV1" => {
            set_text(value, "architecture", "x86_64");
            set_text(value, "defaultAction", "kill-process");
        }
        "NativeReproducibilityRecordV1" => {
            set_text(value, "comparisonAlgorithm", "sha256-byte-for-byte/v1");
            set_value(
                value,
                "builderProvenanceEnvelopeDigests",
                Value::Array(vec![
                    Value::Text("11".repeat(32)),
                    Value::Text("22".repeat(32)),
                ]),
            );
        }
        "B3GenesisOperationV1" => set_text(value, "operationKind", "genesis"),
        "B3ReadOperationV1" => {
            set_text(value, "operationKind", "read");
            set_value(value, "scopeKey", minimal_scope());
        }
        "B3CasOperationV1" => {
            set_text(value, "operationKind", "compare-and-advance");
            set_value(value, "scopeKey", minimal_scope());
            set_value(
                value,
                "callerPurpose",
                Value::Map(vec![
                    ("purpose".into(), Value::Text("rollback".into())),
                    (
                        "authorization".into(),
                        Value::Map(vec![
                            ("kind".into(), Value::Text("rollback".into())),
                            (
                                "authorizationEnvelopeDigest".into(),
                                Value::Text("11".repeat(32)),
                            ),
                        ]),
                    ),
                ]),
            );
        }
        "B3LeaseOperationV1" => {
            set_text(value, "operationKind", "validate-lease");
            set_value(value, "scopeKey", minimal_scope());
        }
        "B3SubscribeOperationV1" => {
            set_text(value, "operationKind", "subscribe-invalidation");
            set_value(value, "scopeKey", minimal_scope());
        }
        _ => {}
    }
    Ok(())
}

impl P2Capture {
    pub fn schema_name(&self) -> &'static str {
        self.schema_name
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn value(&self) -> &Value {
        &self.value
    }
}

fn entries(value: &Value) -> Result<&[(String, Value)], ProtocolError> {
    match value {
        Value::Map(rows) => Ok(rows),
        _ => Err(ProtocolError("P2 object is not a map")),
    }
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, ProtocolError> {
    value
        .field(name)
        .ok_or(ProtocolError("P2 required field missing"))
}

fn recursive_key(value: &Value, keys: &[&str]) -> Result<String, ProtocolError> {
    let mut out = String::new();
    for key in keys {
        match field(value, key)? {
            Value::Text(text) => out.push_str(text),
            Value::Unsigned(number) => out.push_str(&format!("{number:020}")),
            _ => return Err(ProtocolError("P2 array key is not scalar")),
        }
        out.push('\0');
    }
    Ok(out)
}

fn validate_text_pattern(text: &str, pattern: &str) -> bool {
    match pattern {
        "^[A-Za-z0-9][A-Za-z0-9._+@-]{0,4095}$" => {
            !text.is_empty()
                && text.len() <= 4096
                && text
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+@-".contains(&b))
        }
        "^(?:keep-artifact:|keep-source:|oci:)[A-Za-z0-9._:/+@-]+$" => {
            ["keep-artifact:", "keep-source:", "oci:"]
                .iter()
                .any(|prefix| {
                    text.strip_prefix(prefix).is_some_and(|tail| {
                        !tail.is_empty()
                            && tail
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"._:/+@-".contains(&b))
                    })
                })
        }
        "^(?!.*(?:^|\\/)\\.\\.?(?:\\/|$))\\/(?:[A-Za-z0-9._+-]+(?:\\/[A-Za-z0-9._+-]+)*)?$" => {
            canonical_absolute(text)
        }
        "^(?!\\/)(?!.*(?:^|\\/)\\.\\.?(?:\\/|$))(?!.*\\/\\/)[A-Za-z0-9._+-]+(?:\\/[A-Za-z0-9._+-]+)*$" => {
            canonical_relative(text)
        }
        _ => false,
    }
}

pub fn canonical_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains("//")
        && path.split('/').all(|part| {
            !matches!(part, "." | "..")
                && !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        })
}

pub fn validate_recursive(value: &Value, spec: &RSpec) -> Result<(), ProtocolError> {
    match spec {
        RSpec::Identifier { values } => {
            let text = identifier(value)?;
            if values.is_some_and(|set| !set.contains(&text)) {
                return Err(ProtocolError("P2 identifier outside enum"));
            }
        }
        RSpec::Text { values, pattern } => {
            let Value::Text(text) = value else {
                return Err(ProtocolError("P2 text malformed"));
            };
            if text.len() > 4096
                || !text
                    .bytes()
                    .all(|b| b == b'\n' || (0x20..=0x7e).contains(&b))
                || values.is_some_and(|set| !set.contains(&text.as_str()))
                || pattern.is_some_and(|p| !validate_text_pattern(text, p))
            {
                return Err(ProtocolError("P2 bounded text malformed"));
            }
        }
        RSpec::Uint { minimum, maximum } => {
            if !matches!(value, Value::Unsigned(v) if v >= minimum && v <= maximum) {
                return Err(ProtocolError("P2 uint64 bound violated"));
            }
        }
        RSpec::Boolean => {
            if !matches!(value, Value::Bool(_)) {
                return Err(ProtocolError("P2 boolean malformed"));
            }
        }
        RSpec::Digest(_) => {
            parse_digest(text(value)?)?;
        }
        RSpec::Bytes { exact, maximum } => {
            let Value::Bytes(bytes) = value else {
                return Err(ProtocolError("P2 bytes malformed"));
            };
            if exact.is_some_and(|n| bytes.len() != n)
                || bytes.len() > maximum.unwrap_or(1024 * 1024)
            {
                return Err(ProtocolError("P2 byte-string bound violated"));
            }
        }
        RSpec::Nullable(inner) => {
            if !matches!(value, Value::Null) {
                validate_recursive(value, inner)?;
            }
        }
        RSpec::OneOf(variants) => {
            if !variants
                .iter()
                .any(|variant| validate_recursive(value, variant).is_ok())
            {
                return Err(ProtocolError("P2 value matches no variant"));
            }
        }
        RSpec::Record(fields) => {
            let rows = entries(value)?;
            if rows.len() != fields.len() {
                return Err(ProtocolError("P2 record fields not exact"));
            }
            for child in *fields {
                validate_recursive(field(value, child.name)?, &child.spec)?;
            }
        }
        RSpec::Array {
            item,
            minimum,
            maximum,
            sorted_scalar,
            sort_by,
            unique_by,
        } => {
            let Value::Array(items) = value else {
                return Err(ProtocolError("P2 array malformed"));
            };
            if items.len() < *minimum || items.len() > *maximum {
                return Err(ProtocolError("P2 collection bound violated"));
            }
            let mut previous = None;
            let mut seen = BTreeSet::new();
            for child in items {
                validate_recursive(child, item)?;
                if *sorted_scalar {
                    let key = text(child)?.to_owned();
                    if previous.as_ref().is_some_and(|p| p >= &key) {
                        return Err(ProtocolError("P2 scalar array not sorted unique"));
                    }
                    previous = Some(key);
                } else if !sort_by.is_empty() || !unique_by.is_empty() {
                    let order = if sort_by.is_empty() {
                        None
                    } else {
                        Some(recursive_key(child, sort_by)?)
                    };
                    let identity = recursive_key(
                        child,
                        if unique_by.is_empty() {
                            sort_by
                        } else {
                            unique_by
                        },
                    )?;
                    if order
                        .as_ref()
                        .is_some_and(|key| previous.as_ref().is_some_and(|p| p >= key))
                        || !seen.insert(identity)
                    {
                        return Err(ProtocolError("P2 record array order/uniqueness violated"));
                    }
                    previous = order;
                }
            }
        }
        RSpec::Tagged { tag, variants } => {
            let discriminator = text(field(value, tag)?)?;
            let variant = variants
                .iter()
                .find(|variant| variant.name == discriminator)
                .ok_or(ProtocolError("P2 tagged variant unknown"))?;
            validate_recursive(value, &variant.spec)?;
        }
    }
    Ok(())
}
fn exact(value: &Value, specs: &[FieldSpec]) -> Result<(), ProtocolError> {
    let rows = entries(value)?;
    if rows.len() != specs.len() || specs.iter().any(|spec| value.field(spec.name).is_none()) {
        return Err(ProtocolError("P2 schema fields are not exact"));
    }
    Ok(())
}
fn text(value: &Value) -> Result<&str, ProtocolError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(ProtocolError("P2 text malformed")),
    }
}
fn identifier(value: &Value) -> Result<&str, ProtocolError> {
    let value = text(value)?;
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphanumeric() || (i > 0 && b"._:@/-".contains(&b)))
    {
        return Err(ProtocolError("P2 identifier malformed"));
    }
    Ok(value)
}
fn require(value: &Value, name: &str, expected: &str) -> Result<(), ProtocolError> {
    if text(field(value, name)?)? == expected {
        Ok(())
    } else {
        Err(ProtocolError("P2 discriminator mismatch"))
    }
}
fn require_version(value: &Value, expected: u64) -> Result<(), ProtocolError> {
    if matches!(field(value, "version")?, Value::Unsigned(version) if *version == expected) {
        Ok(())
    } else {
        Err(ProtocolError("P2 version mismatch"))
    }
}
fn validate_signature_rows(value: &Value, role_tagged: bool) -> Result<(), ProtocolError> {
    let rows = match value {
        Value::Array(rows) if !rows.is_empty() && rows.len() <= MAX_SIGNATURES => rows,
        _ => return Err(ProtocolError("P2 signatures malformed")),
    };
    let mut prior = None;
    for row in rows {
        let keys = if role_tagged {
            &[
                "keyId",
                "algorithm",
                "keyEpoch",
                "authorizationRole",
                "signature",
            ][..]
        } else {
            &["keyId", "algorithm", "keyEpoch", "signature"][..]
        };
        let map = entries(row)?;
        if map.len() != keys.len() || keys.iter().any(|key| row.field(key).is_none()) {
            return Err(ProtocolError("P2 signature fields not exact"));
        }
        let key = identifier(field(row, "keyId")?)?;
        if prior.is_some_and(|previous| previous >= key) {
            return Err(ProtocolError("P2 signatures not sorted unique"));
        }
        prior = Some(key);
        require(row, "algorithm", "ed25519")?;
        if !matches!(field(row, "keyEpoch")?, Value::Unsigned(_)) {
            return Err(ProtocolError("P2 signature epoch malformed"));
        }
        if role_tagged && !matches!(text(field(row, "authorizationRole")?)?, "root" | "recovery") {
            return Err(ProtocolError("P2 authorization role malformed"));
        }
        if !matches!(field(row, "signature")?, Value::Bytes(bytes) if bytes.len() == 64) {
            return Err(ProtocolError("P2 signature bytes malformed"));
        }
    }
    Ok(())
}

fn operation_spec(value: &Value) -> Result<&'static SchemaSpec, ProtocolError> {
    let kind = text(field(value, "operationKind")?)?;
    let name = match kind {
        "genesis" => "B3GenesisOperationV1",
        "read" => "B3ReadOperationV1",
        "compare-and-advance" => "B3CasOperationV1",
        "validate-lease" => "B3LeaseOperationV1",
        "subscribe-invalidation" => "B3SubscribeOperationV1",
        _ => return Err(ProtocolError("P2 B3 operation kind unknown")),
    };
    Ok(B3_OPERATION_SCHEMAS
        .iter()
        .find(|spec| spec.name == name)
        .unwrap())
}

fn validate_scope(value: &Value) -> Result<(), ProtocolError> {
    let rows = entries(value)?;
    if rows.len() != SCOPE_KEYS.len() || SCOPE_KEYS.iter().any(|key| value.field(key).is_none()) {
        return Err(ProtocolError("P2 scope fields not exact"));
    }
    for key in ["authorityId", "namespace", "scope"] {
        identifier(field(value, key)?)?;
    }
    parse_digest(text(field(value, "genesisRootDigest")?)?)?;
    Ok(())
}

fn validate_special(spec: &SchemaSpec, value: &Value) -> Result<(), ProtocolError> {
    if spec.schema == "keep.native-b3-operation" {
        require(value, "schema", "keep.native-b3-operation")?;
        require_version(value, 1)?;
        let expected_kind = match spec.name {
            "B3GenesisOperationV1" => "genesis",
            "B3ReadOperationV1" => "read",
            "B3CasOperationV1" => "compare-and-advance",
            "B3LeaseOperationV1" => "validate-lease",
            "B3SubscribeOperationV1" => "subscribe-invalidation",
            _ => return Err(ProtocolError("P2 operation metadata unknown")),
        };
        require(value, "operationKind", expected_kind)?;
        if let Some(scope) = value.field("scopeKey") {
            validate_scope(scope)?;
        }
        if spec.name == "B3CasOperationV1" {
            validate_caller_purpose(field(value, "callerPurpose")?)?;
        }
    }
    match spec.name {
        "NativeFdFlagsV1" => validate_fd_flags(value),
        "NativeEnvironmentPolicyV1" => validate_environment(value),
        "NativeIoMaxV1" => validate_io_max(value),
        "NativeLandlockPolicyV1" => validate_landlock(value),
        "NativeLandlockPolicyV2" => validate_landlock_v2(value),
        "NativeSeccompPolicyV1" => validate_seccomp(value),
        "NativeObservationResultV1" => validate_observation(value),
        "NativePeerPolicyV1" => validate_peer_policy(value),
        "NativeControlPolicyV1" => validate_control_policy(value),
        "NativeJournalEntriesV1" => validate_journal_entries(value),
        "NativeTransportIdentityV1" => validate_transport(value),
        "NativeInvocationV1" => validate_invocation(value),
        "NativeComparisonV1" => validate_comparison(value),
        "NativeArtifactInventoryV1" => validate_inventory(value),
        "NativePackagePayloadV1" => validate_package(value),
        "NativeToolchainClosureV1" => validate_toolchain(value),
        "NativeSbomV1" => validate_sbom(value),
        "NativeBuildIdentityV1" => validate_build_identity(value),
        "NativeProvenanceV1" => validate_provenance(value),
        "NativeReproducibilityRecordV1" => validate_repro(value),
        "NativeGenesisEpochV1" => validate_genesis_epoch(value),
        "NativeRootV1" => validate_root(value),
        "NativeTimestampV1" => validate_interval(value, "issuedCounter", "expiresCounter", true),
        "NativeRollbackAuthorizationV1" => validate_rollback(value),
        "NativeRevocationRecoveryV1" => validate_recovery(value),
        "NativeB3ProfileV1" => validate_b3_profile(value),
        "B3StateV1" => validate_b3_state(value),
        "B3ReceiptV1" => validate_b3_receipt(value),
        "B3InvalidationFrameV1" => validate_frame(value),
        "B3InvalidationAckV1" => validate_b3_ack(value),
        _ => Ok(()),
    }
}
fn uint_field(value: &Value, name: &str) -> Result<u64, ProtocolError> {
    match field(value, name)? {
        Value::Unsigned(v) => Ok(*v),
        _ => Err(ProtocolError("P2 uint field malformed")),
    }
}
fn validate_interval(
    value: &Value,
    from: &str,
    until: &str,
    strict: bool,
) -> Result<(), ProtocolError> {
    let a = uint_field(value, from)?;
    let b = uint_field(value, until)?;
    if (strict && b <= a) || (!strict && b < a) {
        return Err(ProtocolError("P2 counter interval invalid"));
    }
    Ok(())
}
fn validate_key_rows(
    value: &Value,
    name: &str,
    global: &mut BTreeSet<String>,
) -> Result<usize, ProtocolError> {
    let rows = match field(value, name)? {
        Value::Array(v) if !v.is_empty() && v.len() <= 32 => v,
        _ => return Err(ProtocolError("P2 key cardinality")),
    };
    let mut prior = None;
    for row in rows {
        exact_keys(
            row,
            &[
                "keyId",
                "algorithm",
                "publicKey",
                "keyEpoch",
                "validFromCounter",
                "validUntilCounter",
            ],
        )?;
        let key = identifier(field(row, "keyId")?)?;
        if key.starts_with("development.")
            || prior.is_some_and(|p| p >= key)
            || !global.insert(key.into())
        {
            return Err(ProtocolError("P2 key identity duplicate/order"));
        }
        prior = Some(key);
        require(row, "algorithm", "ed25519")?;
        if !matches!(field(row,"publicKey")?,Value::Bytes(v)if v.len()==32) {
            return Err(ProtocolError("P2 public key length"));
        }
        validate_interval(row, "validFromCounter", "validUntilCounter", false)?;
    }
    Ok(rows.len())
}
fn validate_genesis_epoch(value: &Value) -> Result<(), ProtocolError> {
    require(value, "trustClass", "production")?;
    let mut keys = BTreeSet::new();
    let count = validate_key_rows(value, "rootKeys", &mut keys)?;
    let threshold = uint_field(value, "rootThreshold")? as usize;
    if threshold == 0 || threshold > count {
        return Err(ProtocolError("P2 genesis root threshold"));
    }
    let participants = match field(value, "participantIds")? {
        Value::Array(v) if !v.is_empty() => v,
        _ => return Err(ProtocolError("P2 genesis participants empty")),
    };
    let mut prior = None;
    for participant in participants {
        let id = identifier(participant)?;
        if prior.is_some_and(|p| p >= id) {
            return Err(ProtocolError("P2 participants not sorted unique"));
        }
        prior = Some(id);
    }
    let minimum = uint_field(value, "minimumParticipants")? as usize;
    if minimum == 0
        || minimum > participants.len()
        || uint_field(value, "requiredWitnesses")? as usize > participants.len()
    {
        return Err(ProtocolError("P2 participant policy invalid"));
    }
    Ok(())
}
fn validate_root(value: &Value) -> Result<(), ProtocolError> {
    require(value, "trustClass", "production")?;
    let epoch = uint_field(value, "rootEpoch")?;
    if (epoch == 0) != matches!(field(value, "predecessorRootEnvelopeDigest")?, Value::Null) {
        return Err(ProtocolError("P2 root predecessor equation"));
    }
    let roles = [
        "root",
        "release",
        "timestamp",
        "revocation",
        "recovery",
        "b3",
        "builder",
        "comparer",
    ];
    let threshold = field(value, "threshold")?;
    exact_keys(threshold, &roles)?;
    let mut global = BTreeSet::new();
    let mut counts = std::collections::BTreeMap::new();
    for role in roles {
        let count = validate_key_rows(value, &format!("{role}Keys"), &mut global)?;
        counts.insert(role, count);
        let n = uint_field(threshold, role)? as usize;
        if n == 0 || n > count {
            return Err(ProtocolError("P2 root threshold invalid"));
        }
    }
    if global.len() > 256 {
        return Err(ProtocolError("P2 combined keys bound"));
    }
    let epochs = match field(value, "keyEpochs")? {
        Value::Array(v) if v.len() == 8 => v,
        _ => return Err(ProtocolError("P2 key epochs cardinality")),
    };
    let sorted_roles = [
        "b3",
        "builder",
        "comparer",
        "recovery",
        "release",
        "revocation",
        "root",
        "timestamp",
    ];
    for (index, row) in epochs.iter().enumerate() {
        exact_keys(row, &["role", "minimumEpoch"])?;
        require(row, "role", sorted_roles[index])?;
        uint_field(row, "minimumEpoch")?;
    }
    Ok(())
}
fn validate_rollback(value: &Value) -> Result<(), ProtocolError> {
    validate_interval(value, "issuedCounter", "expiresCounter", true)?;
    if uint_field(value, "toDeploymentEpoch")? <= uint_field(value, "fromDeploymentEpoch")?
        || uint_field(value, "toArtifactVersion")? < uint_field(value, "minimumArtifactVersion")?
    {
        return Err(ProtocolError("P2 rollback equation"));
    }
    Ok(())
}
const STATE_PROJECTION_KEYS: &[&str] = &[
    "scopeKey",
    "rootEpoch",
    "rootEnvelopeDigest",
    "b3ProfileEnvelopeDigest",
    "headSequence",
    "headEnvelopeDigest",
    "deploymentEpoch",
    "artifactFloor",
    "counter",
    "quarantined",
    "quarantineDigest",
];
fn validate_recovery(value: &Value) -> Result<(), ProtocolError> {
    validate_interval(value, "issuedCounter", "expiresCounter", true)?;
    validate_b3_state(field(value, "expectedB3State")?)?;
    exact_keys(
        field(value, "proposedB3StateProjection")?,
        STATE_PROJECTION_KEYS,
    )?;
    validate_state_projection(field(value, "proposedB3StateProjection")?)?;
    let heads = match field(value, "quarantinedHeadEnvelopeDigests")? {
        Value::Array(v) if !v.is_empty() => v,
        _ => return Err(ProtocolError("P2 recovery heads empty")),
    };
    let mut prior = None;
    for head in heads {
        let digest = text(head)?;
        parse_digest(digest)?;
        if prior.is_some_and(|p| p >= digest) {
            return Err(ProtocolError("P2 recovery heads order"));
        }
        prior = Some(digest);
    }
    if uint_field(value, "selectedSequence")?
        <= uint_field(field(value, "expectedB3State")?, "headSequence")?
    {
        return Err(ProtocolError("P2 recovery sequence not advanced"));
    }
    Ok(())
}
fn validate_state_projection(value: &Value) -> Result<(), ProtocolError> {
    validate_scope(field(value, "scopeKey")?)?;
    for name in [
        "rootEpoch",
        "headSequence",
        "deploymentEpoch",
        "artifactFloor",
        "counter",
    ] {
        uint_field(value, name)?;
    }
    for name in [
        "rootEnvelopeDigest",
        "b3ProfileEnvelopeDigest",
        "headEnvelopeDigest",
        "quarantineDigest",
    ] {
        parse_digest(text(field(value, name)?)?)?;
    }
    if !matches!(field(value, "quarantined")?, Value::Bool(_)) {
        return Err(ProtocolError("P2 projected quarantine flag malformed"));
    }
    Ok(())
}
fn validate_b3_profile(value: &Value) -> Result<(), ProtocolError> {
    require(value, "algorithm", "ed25519")?;
    validate_interval(value, "validFromCounter", "validUntilCounter", false)?;
    let heartbeat = uint_field(value, "maxHeartbeatIntervalMs")?;
    if heartbeat == 0 || heartbeat > 1000 {
        return Err(ProtocolError("P2 heartbeat interval bound"));
    }
    Ok(())
}
fn validate_consumed(value: &Value) -> Result<(), ProtocolError> {
    if matches!(value, Value::Null) {
        return Ok(());
    }
    exact_keys(value, &["kind", "authorizationEnvelopeDigest"])?;
    if !matches!(text(field(value, "kind")?)?, "rollback" | "recovery") {
        return Err(ProtocolError("P2 consumed authorization kind"));
    }
    parse_digest(text(field(value, "authorizationEnvelopeDigest")?)?)?;
    Ok(())
}
fn validate_b3_state(value: &Value) -> Result<(), ProtocolError> {
    exact(value, B3_STATE)?;
    validate_scope(field(value, "scopeKey")?)?;
    validate_consumed(field(value, "consumedAuthorization")?)?;
    Ok(())
}
fn validate_b3_receipt(value: &Value) -> Result<(), ProtocolError> {
    validate_scope(field(value, "scopeKey")?)?;
    let kind = text(field(value, "operationKind")?)?;
    if !matches!(
        kind,
        "genesis" | "read" | "compare-and-advance" | "validate-lease" | "subscribe-invalidation"
    ) {
        return Err(ProtocolError("P2 receipt kind unknown"));
    }
    let committed = matches!(field(value, "committed")?, Value::Bool(true));
    if committed != (kind == "compare-and-advance") {
        return Err(ProtocolError("P2 receipt commit equation"));
    }
    if !committed && field(value, "priorStateDigest")? != field(value, "newStateDigest")? {
        return Err(ProtocolError("P2 readonly receipt mutated"));
    }
    Ok(())
}
fn validate_b3_ack(value: &Value) -> Result<(), ProtocolError> {
    if uint_field(value, "sequence")? == 0 {
        return Err(ProtocolError("P2 invalidation ACK sequence zero"));
    }
    Ok(())
}
fn validate_build_identity(value: &Value) -> Result<(), ProtocolError> {
    if !matches!(text(field(value, "identityKind")?)?, "builder" | "comparer") {
        return Err(ProtocolError("P2 build identity kind unknown"));
    }
    let from = match field(value, "validFromCounter")? {
        Value::Unsigned(v) => *v,
        _ => unreachable!(),
    };
    let until = match field(value, "validUntilCounter")? {
        Value::Unsigned(v) => *v,
        _ => unreachable!(),
    };
    if until < from {
        return Err(ProtocolError("P2 build identity validity inverted"));
    }
    Ok(())
}
fn validate_typed_uri_rows(
    value: &Value,
    name: &str,
    maximum: usize,
    subjects: bool,
) -> Result<(), ProtocolError> {
    let rows = match field(value, name)? {
        Value::Array(r) if r.len() <= maximum => r,
        _ => return Err(ProtocolError("P2 typed URI bound")),
    };
    let mut prior = None;
    for row in rows {
        exact_keys(row, &["uri", "digestType", "digest"])?;
        let uri = text(field(row, "uri")?)?;
        if !matches!(uri.split_once(':'),Some(("keep-artifact"|"keep-source"|"oci",suffix))if !suffix.is_empty())
        {
            return Err(ProtocolError("P2 typed URI grammar"));
        }
        if prior.is_some_and(|p| p >= uri) {
            return Err(ProtocolError("P2 typed URI rows not sorted unique"));
        }
        prior = Some(uri);
        let kind = identifier(field(row, "digestType")?)?;
        if !matches!(
            kind,
            "ArtifactDigest" | "SourceDigest" | "OciBlobDigest" | "SubjectDigest"
        ) {
            return Err(ProtocolError("P2 digest type unknown"));
        }
        let scheme = uri
            .split_once(':')
            .map(|(scheme, _)| scheme)
            .unwrap_or_default();
        let expected = if subjects {
            "SubjectDigest"
        } else {
            match scheme {
                "keep-artifact" => "ArtifactDigest",
                "keep-source" => "SourceDigest",
                "oci" => "OciBlobDigest",
                _ => unreachable!(),
            }
        };
        if kind != expected {
            return Err(ProtocolError("P2 provenance URI/digest type mismatch"));
        }
        parse_digest(text(field(row, "digest")?)?)?;
    }
    Ok(())
}
fn validate_provenance(value: &Value) -> Result<(), ProtocolError> {
    validate_typed_uri_rows(value, "materials", 8192, false)?;
    validate_typed_uri_rows(value, "subjects", 4096, true)?;
    let started = match field(value, "startedCounter")? {
        Value::Unsigned(v) => *v,
        _ => unreachable!(),
    };
    let finished = match field(value, "finishedCounter")? {
        Value::Unsigned(v) => *v,
        _ => unreachable!(),
    };
    if finished < started {
        return Err(ProtocolError("P2 provenance counters inverted"));
    }
    Ok(())
}
fn validate_repro(value: &Value) -> Result<(), ProtocolError> {
    require(value, "comparisonAlgorithm", "sha256-byte-for-byte/v1")?;
    let builders = match field(value, "builderProvenanceEnvelopeDigests")? {
        Value::Array(v) if v.len() >= 2 => v,
        _ => return Err(ProtocolError("P2 repro requires two builders")),
    };
    let mut prior = None;
    for digest in builders {
        let digest = text(digest)?;
        parse_digest(digest)?;
        if prior.is_some_and(|p| p >= digest) {
            return Err(ProtocolError("P2 builder provenances not sorted unique"));
        }
        prior = Some(digest);
    }
    if !matches!(field(value,"disagreements")?,Value::Array(v)if v.is_empty()) {
        return Err(ProtocolError("P2 official disagreements nonempty"));
    }
    Ok(())
}

fn exact_keys(value: &Value, keys: &[&str]) -> Result<(), ProtocolError> {
    if entries(value)?.len() != keys.len() || keys.iter().any(|key| value.field(key).is_none()) {
        return Err(ProtocolError("P2 nested row fields not exact"));
    }
    Ok(())
}
fn validate_inventory(value: &Value) -> Result<(), ProtocolError> {
    let rows = match field(value, "rows")? {
        Value::Array(rows) => rows,
        _ => unreachable!(),
    };
    let mut prior = None;
    for row in rows {
        exact_keys(
            row,
            &[
                "artifactId",
                "kind",
                "digest",
                "size",
                "mode",
                "targetTriple",
                "variant",
                "releaseMember",
            ],
        )?;
        let id = identifier(field(row, "artifactId")?)?;
        if prior.is_some_and(|p| p >= id) {
            return Err(ProtocolError("P2 inventory rows not sorted unique"));
        }
        prior = Some(id);
        if !matches!(
            text(field(row, "kind")?)?,
            "helper"
                | "trampoline"
                | "prober"
                | "provisioner"
                | "role"
                | "policy"
                | "evidence-schema"
        ) || !matches!(text(field(row, "mode")?)?, "0444" | "0555")
        {
            return Err(ProtocolError("P2 inventory enum unknown"));
        }
        parse_digest(text(field(row, "digest")?)?)?;
        if !matches!(field(row, "size")?, Value::Unsigned(_))
            || !matches!(field(row, "releaseMember")?, Value::Bool(_))
        {
            return Err(ProtocolError("P2 inventory row type mismatch"));
        }
        identifier(field(row, "targetTriple")?)?;
        identifier(field(row, "variant")?)?;
    }
    Ok(())
}
fn validate_package(value: &Value) -> Result<(), ProtocolError> {
    let rows = match field(value, "members")? {
        Value::Array(r) => r,
        _ => unreachable!(),
    };
    let mut prior = None;
    for row in rows {
        exact_keys(
            row,
            &[
                "installRoot",
                "relativePath",
                "digest",
                "size",
                "mode",
                "ownerUid",
                "ownerGid",
                "objectType",
            ],
        )?;
        let root = text(field(row, "installRoot")?)?;
        if !matches!(
            root,
            "artifacts" | "policy" | "evidence-schema" | "inventory" | "toolchain"
        ) {
            return Err(ProtocolError("P2 package root unknown"));
        }
        let path = text(field(row, "relativePath")?)?;
        if path.starts_with('/')
            || path.contains("//")
            || path.split('/').any(|p| matches!(p, "" | "." | ".."))
        {
            return Err(ProtocolError("P2 package path malformed"));
        }
        let key = (root, path);
        if prior.is_some_and(|p| p >= key) {
            return Err(ProtocolError("P2 package rows not sorted unique"));
        }
        prior = Some(key);
        parse_digest(text(field(row, "digest")?)?)?;
        if !matches!(
            text(field(row, "objectType")?)?,
            "regular-executable" | "regular-data"
        ) || !matches!(field(row, "size")?, Value::Unsigned(_))
            || !matches!(field(row, "ownerUid")?, Value::Unsigned(_))
            || !matches!(field(row, "ownerGid")?, Value::Unsigned(_))
        {
            return Err(ProtocolError("P2 package row type mismatch"));
        }
    }
    Ok(())
}
fn validate_toolchain(value: &Value) -> Result<(), ProtocolError> {
    let rows = match field(value, "entries")? {
        Value::Array(r) => r,
        _ => unreachable!(),
    };
    let mut prior = None;
    for row in rows {
        exact_keys(row, &["path", "size", "digest", "kind"])?;
        let path = text(field(row, "path")?)?;
        if prior.is_some_and(|p| p >= path) {
            return Err(ProtocolError("P2 toolchain rows not sorted unique"));
        }
        prior = Some(path);
        parse_digest(text(field(row, "digest")?)?)?;
        if !matches!(
            text(field(row, "kind")?)?,
            "compiler"
                | "rustlib"
                | "linker"
                | "sysroot"
                | "vendor-source"
                | "container-manifest"
                | "build-tool"
        ) || !matches!(field(row, "size")?, Value::Unsigned(_))
        {
            return Err(ProtocolError("P2 toolchain row malformed"));
        }
    }
    Ok(())
}
fn validate_sbom(value: &Value) -> Result<(), ProtocolError> {
    let rows = match field(value, "packages")? {
        Value::Array(r) => r,
        _ => unreachable!(),
    };
    let mut prior = None;
    for row in rows {
        exact_keys(
            row,
            &[
                "purl",
                "name",
                "version",
                "license",
                "sourceDigest",
                "checksumAlgorithm",
                "checksum",
            ],
        )?;
        let purl = text(field(row, "purl")?)?;
        if prior.is_some_and(|p| p >= purl) {
            return Err(ProtocolError("P2 SBOM rows not sorted unique"));
        }
        prior = Some(purl);
        require(row, "checksumAlgorithm", "sha256")?;
        parse_digest(text(field(row, "sourceDigest")?)?)?;
        parse_digest(text(field(row, "checksum")?)?)?;
    }
    Ok(())
}

fn validate_control_policy(value: &Value) -> Result<(), ProtocolError> {
    if !matches!(
        text(field(value, "decisionClass")?)?,
        "permit" | "deny" | "measure-only"
    ) {
        return Err(ProtocolError("P2 control decision class unknown"));
    }
    sorted_text_array(
        field(value, "requirements")?,
        &[
            "signature-valid",
            "threshold-met",
            "content-address-match",
            "subject-match",
            "fresh",
            "not-revoked",
            "floor-satisfied",
            "lease-active",
            "isolation-measured",
        ],
    )?;
    Ok(())
}

fn validate_journal_entries(value: &Value) -> Result<(), ProtocolError> {
    let rows = match field(value, "entries")? {
        Value::Array(rows) => rows,
        _ => unreachable!(),
    };
    let mut prior = None;
    for row in rows {
        if entries(row)?.len() != 4
            || ["sequence", "eventCode", "subjectDigest", "counter"]
                .iter()
                .any(|key| row.field(key).is_none())
        {
            return Err(ProtocolError("P2 journal entry fields not exact"));
        }
        let sequence = match field(row, "sequence")? {
            Value::Unsigned(v) => *v,
            _ => return Err(ProtocolError("P2 journal sequence malformed")),
        };
        if prior.is_some_and(|p| sequence != p + 1) {
            return Err(ProtocolError("P2 journal sequence not consecutive"));
        }
        prior = Some(sequence);
        identifier(field(row, "eventCode")?)?;
        parse_digest(text(field(row, "subjectDigest")?)?)?;
        if !matches!(field(row, "counter")?, Value::Unsigned(_)) {
            return Err(ProtocolError("P2 journal counter malformed"));
        }
    }
    Ok(())
}

fn validate_transport(value: &Value) -> Result<(), ProtocolError> {
    if !matches!(
        text(field(value, "transportKind")?)?,
        "unix-seqpacket" | "vsock"
    ) {
        return Err(ProtocolError("P2 transport kind unknown"));
    }
    Ok(())
}

fn validate_invocation(value: &Value) -> Result<(), ProtocolError> {
    let rows = match field(value, "inputs")? {
        Value::Array(rows) => rows,
        _ => unreachable!(),
    };
    let mut prior = None;
    for row in rows {
        if entries(row)?.len() != 2
            || row.field("uri").is_none()
            || row.field("artifactDigest").is_none()
        {
            return Err(ProtocolError("P2 invocation input fields not exact"));
        }
        let uri = text(field(row, "uri")?)?;
        if !matches!(uri.split_once(':'), Some(("keep-artifact" | "keep-source" | "oci", suffix)) if !suffix.is_empty())
        {
            return Err(ProtocolError("P2 invocation URI grammar"));
        }
        if prior.is_some_and(|p| p >= uri) {
            return Err(ProtocolError("P2 invocation inputs not sorted unique"));
        }
        prior = Some(uri);
        parse_digest(text(field(row, "artifactDigest")?)?)?;
    }
    Ok(())
}

fn validate_comparison(value: &Value) -> Result<(), ProtocolError> {
    require(value, "algorithm", "sha256-byte-for-byte/v1")?;
    if field(value, "leftSubjectDigest")? == field(value, "rightSubjectDigest")? {
        return Err(ProtocolError("P2 comparison subjects identical"));
    }
    Ok(())
}

fn validate_peer_policy(value: &Value) -> Result<(), ProtocolError> {
    if ["requiredUid", "requiredGid", "requiredSecurityLabel"]
        .iter()
        .all(|key| matches!(value.field(key), Some(Value::Null)))
    {
        return Err(ProtocolError("P2 peer policy has no constraint"));
    }
    Ok(())
}

fn validate_observation(value: &Value) -> Result<(), ProtocolError> {
    if !matches!(
        text(field(value, "resultCode")?)?,
        "pass" | "fail" | "inconclusive"
    ) {
        return Err(ProtocolError("P2 observation result unknown"));
    }
    let facts = match field(value, "facts")? {
        Value::Array(rows) => rows,
        _ => unreachable!(),
    };
    let mut prior = None;
    for fact in facts {
        if entries(fact)?.len() != 3
            || ["factId", "valueType", "value"]
                .iter()
                .any(|key| fact.field(key).is_none())
        {
            return Err(ProtocolError("P2 fact fields not exact"));
        }
        let id = identifier(field(fact, "factId")?)?;
        if prior.is_some_and(|p| p >= id) {
            return Err(ProtocolError("P2 facts not sorted unique"));
        }
        prior = Some(id);
        match text(field(fact, "valueType")?)? {
            "identifier" => {
                identifier(field(fact, "value")?)?;
            }
            "uint64" if matches!(field(fact, "value")?, Value::Unsigned(_)) => {}
            "boolean" if matches!(field(fact, "value")?, Value::Bool(_)) => {}
            _ => return Err(ProtocolError("P2 fact tagged value mismatch")),
        }
    }
    Ok(())
}

pub fn capture_p2(bytes: &[u8], expected_name: Option<&str>) -> Result<P2Capture, ProtocolError> {
    let limits = if expected_name == Some("NativeEvidenceV1") {
        Limits::EVIDENCE
    } else {
        Limits::MANIFEST
    };
    if bytes.len() > limits.max_bytes {
        return Err(ProtocolError("P2 encoded size exceeds bound"));
    }
    let value = decode_canonical(bytes, limits)?;
    let payload_candidate = value.field("payload").unwrap_or(&value);
    let explicitly_named = expected_name.and_then(|name| {
        P2_SCHEMAS
            .iter()
            .chain(B3_OPERATION_SCHEMAS)
            .find(|spec| spec.name == name)
    });
    let spec = if let Some(spec) = explicitly_named {
        spec
    } else if text(field(payload_candidate, "schema")?)? == "keep.native-b3-operation" {
        operation_spec(payload_candidate)?
    } else {
        let discriminator = text(field(payload_candidate, "schema")?)?;
        P2_SCHEMAS
            .iter()
            .find(|spec| spec.schema == discriminator)
            .ok_or(ProtocolError("P2 schema unknown"))?
    };
    if expected_name.is_some_and(|name| name != spec.name) {
        return Err(ProtocolError("P2 expected schema mismatch"));
    }
    validate_recursive(
        &value,
        recursive_schema_spec(spec.name).ok_or(ProtocolError("P2 recursive schema absent"))?,
    )?;
    let payload = match spec.shape {
        SchemaShape::Unsigned => &value,
        SchemaShape::Envelope | SchemaShape::RootEnvelope => {
            let outer = entries(&value)?;
            if outer.len() != 3
                || ["payload", "payloadDigest", "signatures"]
                    .iter()
                    .any(|key| value.field(key).is_none())
            {
                return Err(ProtocolError("P2 envelope fields not exact"));
            }
            let payload = field(&value, "payload")?;
            if text(field(&value, "payloadDigest")?)? != bare_digest(payload, limits)? {
                return Err(ProtocolError("P2 payload digest mismatch"));
            }
            let role_tagged = spec.shape == SchemaShape::RootEnvelope
                && !matches!(payload.field("rootEpoch"), Some(Value::Unsigned(0)));
            validate_signature_rows(field(&value, "signatures")?, role_tagged)?;
            if payload.field("trustClass").is_some() {
                validate_signer_namespace(payload, field(&value, "signatures")?)?;
            }
            payload
        }
    };
    exact(payload, spec.fields)?;
    if spec.fields.iter().any(|field| field.name == "schema") {
        require(payload, "schema", spec.schema)?;
    }
    if spec.fields.iter().any(|field| field.name == "version") {
        require_version(
            payload,
            if spec.name == "NativeLandlockPolicyV2" {
                2
            } else {
                1
            },
        )?;
    }
    validate_special(spec, payload)?;
    Ok(P2Capture {
        schema_name: spec.name,
        canonical: bytes.to_vec(),
        value,
    })
}

fn validate_signer_namespace(payload: &Value, signatures: &Value) -> Result<(), ProtocolError> {
    let development = text(field(payload, "trustClass")?)? == "development";
    let Value::Array(rows) = signatures else {
        return Err(ProtocolError("P2 signatures malformed"));
    };
    for row in rows {
        let key_id = identifier(field(row, "keyId")?)?;
        if development != key_id.starts_with("development.") {
            return Err(ProtocolError(
                "P2 signer key namespace does not match trust class",
            ));
        }
    }
    Ok(())
}

pub fn bare_digest(value: &Value, limits: Limits) -> Result<String, ProtocolError> {
    Ok(sha256_hex(&encode_bounded(value, limits)?))
}
pub fn envelope_digest(envelope: &Value, limits: Limits) -> Result<String, ProtocolError> {
    let payload = field(envelope, "payload")?;
    if text(field(envelope, "payloadDigest")?)? != bare_digest(payload, limits)? {
        return Err(ProtocolError("P2 payload digest mismatch"));
    }
    Ok(sha256_hex(&encode_bounded(envelope, limits)?))
}
pub fn domain_preimage(
    domain: &'static [u8],
    value: &Value,
    limits: Limits,
) -> Result<Vec<u8>, ProtocolError> {
    if !domain.ends_with(b"/v1\0") {
        return Err(ProtocolError("P2 domain malformed"));
    }
    let canonical = encode_bounded(value, limits)?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(preimage)
}
pub fn operation_digest(name: &str, value: &Value) -> Result<String, ProtocolError> {
    let spec = B3_OPERATION_SCHEMAS
        .iter()
        .find(|spec| spec.name == name)
        .ok_or(ProtocolError("P2 operation schema unknown"))?;
    exact(value, spec.fields)?;
    validate_special(spec, value)?;
    Ok(sha256_hex(&domain_preimage(
        spec.signature_domain.unwrap(),
        value,
        Limits::MANIFEST,
    )?))
}
pub fn signature_preimage(name: &str, payload: &Value) -> Result<[u8; 64], ProtocolError> {
    let spec = P2_SCHEMAS
        .iter()
        .find(|spec| spec.name == name)
        .ok_or(ProtocolError("P2 signed schema unknown"))?;
    let domain = if spec.name == "NativeRootV1" {
        match payload.field("rootEpoch") {
            Some(Value::Unsigned(0)) => b"keep.native-root-genesis/v1\0".as_slice(),
            _ => b"keep.native-root-update/v1\0".as_slice(),
        }
    } else {
        spec.signature_domain
            .ok_or(ProtocolError("P2 schema is unsigned"))?
    };
    exact(payload, spec.fields)?;
    let preimage = domain_preimage(domain, payload, Limits::MANIFEST)?;
    sha512(&preimage)
}

/// Dependency-free FIPS 180-4 SHA-512 used only for frozen signature-message construction.
pub fn sha512(bytes: &[u8]) -> Result<[u8; 64], ProtocolError> {
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];
    let bit_length = (bytes.len() as u128)
        .checked_mul(8)
        .ok_or(ProtocolError("SHA-512 length overflow"))?;
    let padded_length = bytes
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(16))
        .and_then(|n| n.checked_add(127))
        .map(|n| n / 128 * 128)
        .ok_or(ProtocolError("SHA-512 length overflow"))?;
    let mut padded = Vec::new();
    padded
        .try_reserve_exact(padded_length)
        .map_err(|_| ProtocolError("SHA-512 allocation failed"))?;
    padded.extend_from_slice(bytes);
    padded.push(0x80);
    padded.resize(padded_length - 16, 0);
    padded.extend_from_slice(&bit_length.to_be_bytes());
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    for chunk in padded.chunks_exact(128) {
        let mut w = [0u64; 80];
        for (i, word) in w[..16].iter_mut().enumerate() {
            *word = u64::from_be_bytes(chunk[i * 8..i * 8 + 8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
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
        for (state, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *state = (*state).wrapping_add(v);
        }
    }
    let mut out = [0u8; 64];
    for (index, word) in h.iter().enumerate() {
        out[index * 8..index * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    Ok(out)
}

fn validate_caller_purpose(value: &Value) -> Result<(), ProtocolError> {
    let rows = entries(value)?;
    if rows.len() != 2 || value.field("purpose").is_none() || value.field("authorization").is_none()
    {
        return Err(ProtocolError("P2 caller purpose fields not exact"));
    }
    let purpose = text(field(value, "purpose")?)?;
    let authorization = field(value, "authorization")?;
    let auth_rows = entries(authorization)?;
    if auth_rows.len() != 2
        || authorization.field("kind").is_none()
        || authorization.field("authorizationEnvelopeDigest").is_none()
    {
        return Err(ProtocolError("P2 caller authorization fields not exact"));
    }
    let kind = text(field(authorization, "kind")?)?;
    let expected = match purpose {
        "root-update" => "root-update",
        "revocation-advance" => "revocation",
        "rollback" => "rollback",
        "recovery" => "recovery",
        "deployment-advance" => "deployment",
        _ => return Err(ProtocolError("P2 caller purpose unknown")),
    };
    if kind != expected {
        return Err(ProtocolError("P2 caller purpose/kind mismatch"));
    }
    parse_digest(text(field(authorization, "authorizationEnvelopeDigest")?)?)?;
    Ok(())
}
fn sorted_text_array<'a>(
    value: &'a Value,
    allowed: &[&str],
) -> Result<Vec<&'a str>, ProtocolError> {
    let rows = match value {
        Value::Array(rows) => rows,
        _ => return Err(ProtocolError("P2 array malformed")),
    };
    let mut out = Vec::new();
    for row in rows {
        let text = text(row)?;
        if !allowed.contains(&text) || out.last().is_some_and(|prior| *prior >= text) {
            return Err(ProtocolError("P2 array not sorted unique or enum unknown"));
        }
        out.push(text);
    }
    Ok(out)
}
fn validate_fd_flags(value: &Value) -> Result<(), ProtocolError> {
    let flags = sorted_text_array(
        field(value, "flags")?,
        &[
            "O_RDONLY",
            "O_CLOEXEC",
            "O_NOFOLLOW",
            "O_PATH",
            "O_DIRECTORY",
        ],
    )?;
    sorted_text_array(
        field(value, "seals")?,
        &[
            "F_SEAL_WRITE",
            "F_SEAL_SHRINK",
            "F_SEAL_GROW",
            "F_SEAL_EXEC",
            "F_SEAL_SEAL",
        ],
    )?;
    let close = matches!(field(value, "closeOnExec")?, Value::Bool(true));
    if close != flags.contains(&"O_CLOEXEC") {
        return Err(ProtocolError("P2 close-on-exec contradiction"));
    }
    Ok(())
}
fn validate_environment(value: &Value) -> Result<(), ProtocolError> {
    sorted_text_array(field(value, "allowedVariables")?, &[]).or_else(|_| {
        let rows = match field(value, "allowedVariables")? {
            Value::Array(rows) => rows,
            _ => return Err(ProtocolError("P2 environment array malformed")),
        };
        let mut prior = None;
        for row in rows {
            let id = identifier(row)?;
            if prior.is_some_and(|p| p >= id) {
                return Err(ProtocolError("P2 environment variables not sorted unique"));
            }
            prior = Some(id);
        }
        Ok(Vec::new())
    })?;
    if !matches!(
        text(field(value, "workingDirectoryPolicy")?)?,
        "empty" | "fixed-source-root"
    ) || !matches!(
        text(field(value, "networkPolicy")?)?,
        "denied" | "builder-isolated"
    ) {
        return Err(ProtocolError("P2 environment policy enum unknown"));
    }
    Ok(())
}
fn validate_io_max(value: &Value) -> Result<(), ProtocolError> {
    require(value, "defaultPolicy", "deny-unlisted")?;
    let rows = match field(value, "rows")? {
        Value::Array(rows) => rows,
        _ => unreachable!(),
    };
    let keys = [
        "deviceMajor",
        "deviceMinor",
        "readBytesPerSecond",
        "writeBytesPerSecond",
        "readIops",
        "writeIops",
    ];
    let mut prior = None;
    for row in rows {
        let map = entries(row)?;
        if map.len() != keys.len() || keys.iter().any(|key| row.field(key).is_none()) {
            return Err(ProtocolError("P2 io-max row fields not exact"));
        }
        let major = match field(row, "deviceMajor")? {
            Value::Unsigned(v) => *v,
            _ => return Err(ProtocolError("P2 io-max device malformed")),
        };
        let minor = match field(row, "deviceMinor")? {
            Value::Unsigned(v) => *v,
            _ => return Err(ProtocolError("P2 io-max device malformed")),
        };
        if prior.is_some_and(|p| p >= (major, minor)) {
            return Err(ProtocolError("P2 io-max rows not sorted unique"));
        }
        prior = Some((major, minor));
        let mut present = false;
        for key in &keys[2..] {
            match field(row, key)? {
                Value::Null => {}
                Value::Unsigned(_) => present = true,
                _ => return Err(ProtocolError("P2 io-max limit malformed")),
            }
        }
        if !present {
            return Err(ProtocolError("P2 io-max row has no limit"));
        }
    }
    Ok(())
}
const LANDLOCK_V2_FS: &[&str] = &[
    "execute",
    "ioctl-dev",
    "make-block",
    "make-char",
    "make-dir",
    "make-fifo",
    "make-reg",
    "make-sock",
    "make-sym",
    "read-dir",
    "read-file",
    "refer",
    "remove-dir",
    "remove-file",
    "resolve-unix",
    "truncate",
    "write-file",
];
const LANDLOCK_V2_NET: &[&str] = &["bind-tcp", "bind-udp", "connect-send-udp", "connect-tcp"];
const LANDLOCK_V2_FS_ABI4: &[&str] = &[
    "execute",
    "make-block",
    "make-char",
    "make-dir",
    "make-fifo",
    "make-reg",
    "make-sock",
    "make-sym",
    "read-dir",
    "read-file",
    "refer",
    "remove-dir",
    "remove-file",
    "truncate",
    "write-file",
];
const LANDLOCK_V2_NET_ABI4_9: &[&str] = &["bind-tcp", "connect-tcp"];
const LANDLOCK_SCOPE: &[&str] = &["abstract-unix-socket", "signal"];

fn validate_landlock(value: &Value) -> Result<(), ProtocolError> {
    if !matches!(field(value, "minimumAbi")?, Value::Unsigned(1..=255)) {
        return Err(ProtocolError("P2 landlock ABI out of range"));
    }
    const FS: &[&str] = &[
        "execute",
        "write-file",
        "read-file",
        "read-dir",
        "remove-dir",
        "remove-file",
        "make-char",
        "make-dir",
        "make-reg",
        "make-sock",
        "make-fifo",
        "make-block",
        "make-sym",
        "refer",
        "truncate",
        "ioctl-dev",
    ];
    const NET: &[&str] = &["bind-tcp", "connect-tcp"];
    const SCOPE: &[&str] = &["signal", "abstract-unix-socket"];
    let handled_fs = sorted_text_array(field(value, "handledFilesystemRights")?, FS)?;
    let handled_net = sorted_text_array(field(value, "handledNetworkRights")?, NET)?;
    sorted_text_array(field(value, "handledScopeRights")?, SCOPE)?;
    let rules = match field(value, "rules")? {
        Value::Array(rows) => rows,
        _ => unreachable!(),
    };
    let mut prior = String::new();
    for row in rules {
        let kind = text(field(row, "kind")?)?;
        let sort = if kind == "path-beneath" {
            let keys = ["kind", "path", "accessRights"];
            if entries(row)?.len() != 3 || keys.iter().any(|k| row.field(k).is_none()) {
                return Err(ProtocolError("P2 landlock path rule fields not exact"));
            }
            let path = text(field(row, "path")?)?;
            if !canonical_absolute(path) {
                return Err(ProtocolError("P2 landlock path malformed"));
            }
            let rights = sorted_text_array(field(row, "accessRights")?, FS)?;
            if rights.iter().any(|right| !handled_fs.contains(right)) {
                return Err(ProtocolError("P2 landlock rule right not handled"));
            }
            format!("0:{path}")
        } else if kind == "tcp-port" {
            let keys = ["kind", "port", "accessRights"];
            if entries(row)?.len() != 3 || keys.iter().any(|k| row.field(k).is_none()) {
                return Err(ProtocolError("P2 landlock port rule fields not exact"));
            }
            let port = match field(row, "port")? {
                Value::Unsigned(v @ 1..=65535) => *v,
                _ => return Err(ProtocolError("P2 landlock port malformed")),
            };
            let rights = sorted_text_array(field(row, "accessRights")?, NET)?;
            if rights.iter().any(|right| !handled_net.contains(right)) {
                return Err(ProtocolError("P2 landlock rule right not handled"));
            }
            format!("1:{port:05}")
        } else {
            return Err(ProtocolError("P2 landlock rule kind unknown"));
        };
        if !prior.is_empty() && prior >= sort {
            return Err(ProtocolError("P2 landlock rules not sorted unique"));
        }
        prior = sort;
    }
    Ok(())
}

fn validate_landlock_v2(value: &Value) -> Result<(), ProtocolError> {
    if !matches!(field(value, "minimumAbi")?, Value::Unsigned(4..=10))
        || field(value, "reviewedMaximumAbi")? != &Value::Unsigned(10)
    {
        return Err(ProtocolError("P2 Landlock v2 ABI range is not reviewed"));
    }
    let effective_abi = match field(value, "effectiveAbi")? {
        Value::Unsigned(v @ 4..=10) => *v,
        _ => {
            return Err(ProtocolError(
                "P2 Landlock v2 effective ABI is not reviewed",
            ));
        }
    };
    let minimum_abi = match field(value, "minimumAbi")? {
        Value::Unsigned(v) => *v,
        _ => unreachable!(),
    };
    if effective_abi < minimum_abi {
        return Err(ProtocolError(
            "P2 Landlock v2 effective ABI is below minimum",
        ));
    }
    let handled_fs = sorted_text_array(field(value, "handledFilesystemRights")?, LANDLOCK_V2_FS)?;
    let handled_net = sorted_text_array(field(value, "handledNetworkRights")?, LANDLOCK_V2_NET)?;
    let handled_scope = sorted_text_array(field(value, "handledScopeRights")?, LANDLOCK_SCOPE)?;
    let expected_fs: Vec<&&str> = LANDLOCK_V2_FS
        .iter()
        .filter(|right| {
            **right != "resolve-unix" && (**right != "ioctl-dev" || effective_abi >= 5)
                || (**right == "resolve-unix" && effective_abi >= 9)
        })
        .collect();
    let expected_net = if effective_abi >= 10 {
        LANDLOCK_V2_NET
    } else {
        LANDLOCK_V2_NET_ABI4_9
    };
    let expected_scope = if effective_abi >= 6 {
        LANDLOCK_SCOPE
    } else {
        &[]
    };
    if handled_fs
        .iter()
        .copied()
        .ne(expected_fs.into_iter().copied())
        || handled_net.as_slice() != expected_net
        || handled_scope.as_slice() != expected_scope
    {
        return Err(ProtocolError(
            "P2 Landlock v2 handled-right closure is incomplete",
        ));
    }
    let rules = match field(value, "rules")? {
        Value::Array(rows) => rows,
        _ => unreachable!(),
    };
    let mut prior = String::new();
    for row in rules {
        let kind = text(field(row, "kind")?)?;
        let keys = [
            "kind",
            if kind == "path-beneath" {
                "path"
            } else {
                "port"
            },
            "accessRights",
        ];
        if entries(row)?.len() != 3 || keys.iter().any(|key| row.field(key).is_none()) {
            return Err(ProtocolError("P2 Landlock v2 rule fields not exact"));
        }
        let sort = if kind == "path-beneath" {
            let path = text(field(row, "path")?)?;
            if !canonical_absolute(path) {
                return Err(ProtocolError("P2 Landlock v2 path malformed"));
            }
            let rights = sorted_text_array(field(row, "accessRights")?, LANDLOCK_V2_FS)?;
            if rights.iter().any(|right| !handled_fs.contains(right)) {
                return Err(ProtocolError("P2 Landlock v2 path right not handled"));
            }
            format!("path-beneath\0{path}")
        } else if kind == "tcp-port" || kind == "udp-port" {
            let port = match field(row, "port")? {
                Value::Unsigned(value @ 1..=65535) if kind == "tcp-port" => *value,
                Value::Unsigned(value @ 0..=65535) if kind == "udp-port" => *value,
                _ => return Err(ProtocolError("P2 Landlock v2 port malformed")),
            };
            let admitted = if kind == "tcp-port" {
                &["bind-tcp", "connect-tcp"][..]
            } else {
                &["bind-udp", "connect-send-udp"][..]
            };
            let rights = sorted_text_array(field(row, "accessRights")?, admitted)?;
            if rights.iter().any(|right| !handled_net.contains(right)) {
                return Err(ProtocolError("P2 Landlock v2 network right not handled"));
            }
            format!("{kind}\0{port:05}")
        } else {
            return Err(ProtocolError("P2 Landlock v2 rule kind unknown"));
        };
        if !prior.is_empty() && prior >= sort {
            return Err(ProtocolError("P2 Landlock v2 rules not sorted unique"));
        }
        prior = sort;
    }
    Ok(())
}
fn canonical_absolute(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 4096
        && !path.contains("//")
        && path.strip_prefix('/').is_some_and(|tail| {
            tail.is_empty()
                || tail
                    .split('/')
                    .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
        })
        && path
            .bytes()
            .all(|b| b == b'/' || b.is_ascii_alphanumeric() || b"._@-".contains(&b))
}
fn validate_seccomp(value: &Value) -> Result<(), ProtocolError> {
    if !matches!(text(field(value, "architecture")?)?, "x86_64" | "aarch64")
        || text(field(value, "defaultAction")?)? != "kill-process"
    {
        return Err(ProtocolError("P2 seccomp header malformed"));
    }
    let rules = match field(value, "rules")? {
        Value::Array(r) => r,
        _ => unreachable!(),
    };
    let mut prior = None;
    for row in rules {
        let keys = ["syscall", "action", "errno", "arguments"];
        if entries(row)?.len() != 4 || keys.iter().any(|k| row.field(k).is_none()) {
            return Err(ProtocolError("P2 seccomp rule fields not exact"));
        }
        let syscall = identifier(field(row, "syscall")?)?;
        if prior.is_some_and(|p| p >= syscall) {
            return Err(ProtocolError("P2 seccomp rules not sorted unique"));
        }
        prior = Some(syscall);
        let action = text(field(row, "action")?)?;
        if !matches!(action, "allow" | "kill-process" | "errno") {
            return Err(ProtocolError("P2 seccomp action unknown"));
        }
        if (action == "errno") != matches!(field(row, "errno")?, Value::Unsigned(_)) {
            return Err(ProtocolError("P2 seccomp errno contradiction"));
        }
        let args = match field(row, "arguments")? {
            Value::Array(a) if a.len() <= 6 => a,
            _ => return Err(ProtocolError("P2 seccomp arguments bound")),
        };
        let mut pi = None;
        for arg in args {
            let ks = ["index", "operator", "value", "mask"];
            if entries(arg)?.len() != 4 || ks.iter().any(|k| arg.field(k).is_none()) {
                return Err(ProtocolError("P2 seccomp argument fields not exact"));
            }
            let idx = match field(arg, "index")? {
                Value::Unsigned(v @ 0..=5) => *v,
                _ => return Err(ProtocolError("P2 seccomp argument index")),
            };
            if pi.is_some_and(|p| p >= idx) {
                return Err(ProtocolError("P2 seccomp arguments not sorted unique"));
            }
            pi = Some(idx);
            let op = text(field(arg, "operator")?)?;
            if !matches!(op, "eq" | "ne" | "lt" | "le" | "gt" | "ge" | "masked-eq")
                || !matches!(field(arg, "value")?, Value::Unsigned(_))
                || (op == "masked-eq") != matches!(field(arg, "mask")?, Value::Unsigned(_))
            {
                return Err(ProtocolError("P2 seccomp argument malformed"));
            }
        }
    }
    Ok(())
}
fn validate_frame(value: &Value) -> Result<(), ProtocolError> {
    let kind = text(field(value, "frameKind")?)?;
    let prior = match field(value, "priorGeneration")? {
        Value::Unsigned(v) => *v,
        _ => unreachable!(),
    };
    let new = match field(value, "newGeneration")? {
        Value::Unsigned(v) => *v,
        _ => unreachable!(),
    };
    if !matches!(field(value, "sequence")?, Value::Unsigned(1..))
        || !((kind == "heartbeat" && prior == new) || (kind == "invalidated" && new > prior))
    {
        return Err(ProtocolError("P2 invalidation frame equation"));
    }
    let sequence = uint_field(value, "sequence")?;
    if (sequence == 1) != matches!(field(value, "priorAckDigest")?, Value::Null) {
        return Err(ProtocolError("P2 invalidation ACK chain equation"));
    }
    Ok(())
}

pub fn schema_metadata_is_closed() -> Result<(), ProtocolError> {
    let mut names = BTreeSet::new();
    let mut signed_domains = BTreeSet::new();
    for spec in P2_SCHEMAS.iter().chain(B3_OPERATION_SCHEMAS) {
        if !names.insert(spec.name) {
            return Err(ProtocolError("P2 schema name duplicate"));
        }
        let mut fields = BTreeSet::new();
        for field in spec.fields {
            if !fields.insert(field.name) {
                return Err(ProtocolError("P2 schema field duplicate"));
            }
        }
        if let Some(domain) = spec.signature_domain {
            if !signed_domains.insert(domain) {
                return Err(ProtocolError("P2 domain duplicate"));
            }
        }
    }
    let _ = OP_COMMON;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn digest() -> Value {
        Value::Text("ab".repeat(32))
    }
    fn scope() -> Value {
        Value::Map(vec![
            ("authorityId".into(), Value::Text("authority.1".into())),
            ("namespace".into(), Value::Text("native".into())),
            ("scope".into(), Value::Text("release".into())),
            ("genesisRootDigest".into(), digest()),
        ])
    }
    fn read_operation() -> Value {
        Value::Map(vec![
            (
                "schema".into(),
                Value::Text("keep.native-b3-operation".into()),
            ),
            ("version".into(), Value::Unsigned(1)),
            ("operationKind".into(), Value::Text("read".into())),
            ("scopeKey".into(), scope()),
            ("requestNonce".into(), Value::Bytes(vec![7; 32])),
        ])
    }
    #[test]
    fn metadata_is_closed_and_dependency_free() {
        schema_metadata_is_closed().unwrap();
        assert!(P2_SCHEMAS.len() >= 28);
        assert_eq!(B3_OPERATION_SCHEMAS.len(), 5);
        let detail = recursive_schema_metadata().unwrap();
        assert!(!detail.is_empty());
    }
    #[test]
    fn recursive_nested_type_and_bound_neuters_refuse() {
        let spec = recursive_schema_spec("NativeSeccompPolicyV1").unwrap();
        let mut value = minimal_recursive(spec);
        let Value::Map(rows) = &mut value else {
            unreachable!()
        };
        let Value::Array(rules) = &mut rows.iter_mut().find(|(key, _)| key == "rules").unwrap().1
        else {
            unreachable!()
        };
        rules.push(Value::Map(vec![("syscall".into(), Value::Unsigned(7))]));
        assert!(
            validate_recursive(&value, spec).is_err(),
            "nested scalar type neuter accepted"
        );

        let array = RSpec::Array {
            item: &RSpec::Uint {
                minimum: 0,
                maximum: 1,
            },
            minimum: 0,
            maximum: 1,
            sorted_scalar: false,
            sort_by: &[],
            unique_by: &[],
        };
        assert!(
            validate_recursive(
                &Value::Array(vec![Value::Unsigned(0), Value::Unsigned(0)]),
                &array
            )
            .is_err(),
            "nested maximum+1 accepted"
        );
    }
    #[test]
    fn invalidation_ack_chain_and_frozen_p1_identifier_neuters() {
        let schema = P2_SCHEMAS
            .iter()
            .find(|schema| schema.name == "B3InvalidationFrameV1")
            .unwrap();
        let recursive = recursive_schema_spec(schema.name).unwrap();
        let RSpec::Record(envelope) = recursive else {
            unreachable!()
        };
        let payload_spec = &envelope
            .iter()
            .find(|field| field.name == "payload")
            .unwrap()
            .spec;
        let mut frame = minimal_recursive(payload_spec);
        specialize_minimal(schema, &mut frame).unwrap();
        set_value(&mut frame, "priorAckDigest", digest());
        assert!(
            validate_frame(&frame).is_err(),
            "sequence 1 accepted a prior ACK"
        );
        set_uint(&mut frame, "sequence", 2);
        set_value(&mut frame, "priorAckDigest", Value::Null);
        assert!(
            validate_frame(&frame).is_err(),
            "sequence >1 accepted a missing prior ACK"
        );
        set_value(&mut frame, "priorAckDigest", digest());
        validate_frame(&frame).unwrap();

        let id_spec = RSpec::Identifier { values: None };
        validate_recursive(&Value::Text(format!("a{}@", "x".repeat(126))), &id_spec).unwrap();
        assert!(
            validate_recursive(&Value::Text(format!("a{}", "x".repeat(128))), &id_spec).is_err(),
            "129-byte identifier accepted"
        );
        assert!(
            validate_recursive(&Value::Text("a+b".into()), &id_spec).is_err(),
            "P1-excluded plus accepted"
        );
    }
    #[test]
    fn signer_namespace_and_provenance_uri_type_joins_refuse_cross_family_mutants() {
        let audited: BTreeSet<_> = P2_SCHEMAS
            .iter()
            .filter_map(|schema| {
                if schema.shape == SchemaShape::RootEnvelope
                    || schema.shape == SchemaShape::Unsigned
                {
                    return None;
                }
                let RSpec::Record(outer) = recursive_schema_spec(schema.name)? else {
                    return None;
                };
                let RSpec::Record(payload) =
                    &outer.iter().find(|field| field.name == "payload")?.spec
                else {
                    return None;
                };
                payload
                    .iter()
                    .any(|field| field.name == "trustClass")
                    .then_some(schema.name)
            })
            .collect();
        assert_eq!(
            audited,
            BTreeSet::from([
                "NativeB3ProfileV1",
                "NativeBuildIdentityV1",
                "NativeRevocationRecoveryV1",
                "NativeRollbackAuthorizationV1",
                "NativeRootCeremonyRecordV1",
                "NativeTimestampV1"
            ])
        );
        for name in audited {
            let production = Value::Map(vec![(
                "trustClass".into(),
                Value::Text("production".into()),
            )]);
            let development = Value::Map(vec![(
                "trustClass".into(),
                Value::Text("development".into()),
            )]);
            let prod_signature = minimal_signatures(false);
            let mut dev_signature = minimal_signatures(false);
            let Value::Array(rows) = &mut dev_signature else {
                unreachable!()
            };
            set_text(&mut rows[0], "keyId", "development.key.1");
            validate_signer_namespace(&production, &prod_signature)
                .unwrap_or_else(|_| panic!("{name} production join"));
            validate_signer_namespace(&development, &dev_signature)
                .unwrap_or_else(|_| panic!("{name} development join"));
            assert!(
                validate_signer_namespace(&production, &dev_signature).is_err(),
                "{name} accepted development signer in production"
            );
            assert!(
                validate_signer_namespace(&development, &prod_signature).is_err(),
                "{name} accepted production signer in development"
            );
        }

        let row = |uri: &str, kind: &str| {
            Value::Map(vec![
                ("uri".into(), Value::Text(uri.into())),
                ("digestType".into(), Value::Text(kind.into())),
                ("digest".into(), digest()),
            ])
        };
        let provenance =
            |name: &str, row: Value| Value::Map(vec![(name.into(), Value::Array(vec![row]))]);
        validate_typed_uri_rows(
            &provenance("materials", row("keep-source:src", "SourceDigest")),
            "materials",
            8192,
            false,
        )
        .unwrap();
        assert!(
            validate_typed_uri_rows(
                &provenance("materials", row("keep-source:src", "ArtifactDigest")),
                "materials",
                8192,
                false
            )
            .is_err()
        );
        assert!(
            validate_typed_uri_rows(
                &provenance("materials", row("oci:image", "UnknownDigest")),
                "materials",
                8192,
                false
            )
            .is_err()
        );
        assert!(
            validate_typed_uri_rows(
                &provenance("subjects", row("keep-artifact:bin", "ArtifactDigest")),
                "subjects",
                4096,
                true
            )
            .is_err()
        );
    }
    #[test]
    fn root_initial_and_successor_signatures_join_production_namespace() {
        let (_, bytes) = minimal_p2_corpus()
            .unwrap()
            .into_iter()
            .find(|(name, _)| *name == "NativeRootV1")
            .unwrap();
        let initial = decode_canonical(&bytes, Limits::MANIFEST).unwrap();
        let mut initial_mutant = initial.clone();
        let Value::Array(signatures) = initial_mutant.field("signatures").unwrap().clone() else {
            unreachable!()
        };
        let mut bad_signatures = signatures;
        set_text(&mut bad_signatures[0], "keyId", "development.root.1");
        set_value(
            &mut initial_mutant,
            "signatures",
            Value::Array(bad_signatures),
        );
        assert!(
            capture_p2(
                &encode_bounded(&initial_mutant, Limits::MANIFEST).unwrap(),
                Some("NativeRootV1")
            )
            .is_err()
        );

        let mut successor = initial;
        let mut payload = successor.field("payload").unwrap().clone();
        set_uint(&mut payload, "rootEpoch", 1);
        set_value(&mut payload, "predecessorRootEnvelopeDigest", digest());
        let payload_digest = bare_digest(&payload, Limits::MANIFEST).unwrap();
        set_value(&mut successor, "payload", payload);
        set_text(&mut successor, "payloadDigest", &payload_digest);
        let Value::Array(mut signatures) = successor.field("signatures").unwrap().clone() else {
            unreachable!()
        };
        let Value::Map(fields) = &mut signatures[0] else {
            unreachable!()
        };
        fields.push(("authorizationRole".into(), Value::Text("root".into())));
        set_value(&mut successor, "signatures", Value::Array(signatures));
        let successor_bytes = encode_bounded(&successor, Limits::MANIFEST).unwrap();
        capture_p2(&successor_bytes, Some("NativeRootV1")).unwrap();

        let mut successor_mutant = successor;
        let Value::Array(mut signatures) = successor_mutant.field("signatures").unwrap().clone()
        else {
            unreachable!()
        };
        set_text(&mut signatures[0], "keyId", "development.root.1");
        set_value(
            &mut successor_mutant,
            "signatures",
            Value::Array(signatures),
        );
        assert!(
            capture_p2(
                &encode_bounded(&successor_mutant, Limits::MANIFEST).unwrap(),
                Some("NativeRootV1")
            )
            .is_err()
        );
    }
    #[test]
    fn b3_read_construction_golden_and_cross_kind_separation() {
        let value = read_operation();
        let bytes = encode_bounded(&value, Limits::MANIFEST).unwrap();
        let capture = capture_p2(&bytes, Some("B3ReadOperationV1")).unwrap();
        assert_eq!(capture.canonical_bytes(), bytes);
        assert_eq!(
            operation_digest("B3ReadOperationV1", &value).unwrap(),
            "03bca24e69bc5e74784037667f8c569d0fab416d509f755b1b3c7d7983f0e483"
        );
        assert!(operation_digest("B3LeaseOperationV1", &value).is_err());
    }
    #[test]
    fn exact_unknown_type_and_nonce_boundaries_refuse() {
        let mut value = read_operation();
        let Value::Map(rows) = &mut value else {
            unreachable!()
        };
        rows.push(("extra".into(), Value::Null));
        assert!(capture_p2(&encode_bounded(&value, Limits::MANIFEST).unwrap(), None).is_err());
        let mut value = read_operation();
        let Value::Map(rows) = &mut value else {
            unreachable!()
        };
        rows.iter_mut()
            .find(|(k, _)| k == "requestNonce")
            .unwrap()
            .1 = Value::Bytes(vec![0; 33]);
        assert!(capture_p2(&encode_bounded(&value, Limits::MANIFEST).unwrap(), None).is_err());
    }
    #[test]
    fn max_plus_one_and_aggregate_bounds_refuse() {
        let value = Value::Map(vec![
            ("schema".into(), Value::Text("keep.native-io-max".into())),
            ("version".into(), Value::Unsigned(1)),
            ("defaultPolicy".into(), Value::Text("deny-unlisted".into())),
            ("rows".into(), Value::Array(vec![Value::Null; 129])),
        ]);
        assert!(capture_p2(&encode_bounded(&value, Limits::MANIFEST).unwrap(), None).is_err());
        let aggregate = Value::Array(vec![Value::Null; 65_536]);
        assert!(encode_bounded(&aggregate, Limits::MANIFEST).is_err());
    }
    #[test]
    fn semantic_digest_newtypes_do_not_substitute() {
        let a = RootEnvelopeDigest::parse(&"ab".repeat(32)).unwrap();
        let b = DeploymentEnvelopeDigest::parse(&"ab".repeat(32)).unwrap();
        assert_eq!(a.bytes(), b.bytes());
        assert_eq!(a.to_hex(), "ab".repeat(32));
    }
    #[test]
    fn sha512_matches_fips_and_node_padding_boundaries() {
        for (input, expected) in [
            (
                Vec::new(),
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
            (
                b"abc".to_vec(),
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                vec![b'a'; 111],
                "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2",
            ),
            (
                vec![b'a'; 112],
                "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca",
            ),
            (
                vec![b'a'; 127],
                "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502",
            ),
            (
                vec![b'a'; 128],
                "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321",
            ),
        ] {
            assert_eq!(hex(&sha512(&input).unwrap()), expected);
            assert_ne!(
                sha512(&input).unwrap().as_slice(),
                input.as_slice(),
                "raw-preimage neuter"
            );
        }
    }
    #[test]
    fn authority_semantic_neuters_refuse_intervals_heartbeat_and_recovery_projection_extensions() {
        let profile = Value::Map(vec![
            ("algorithm".into(), Value::Text("ed25519".into())),
            ("validFromCounter".into(), Value::Unsigned(1)),
            ("validUntilCounter".into(), Value::Unsigned(2)),
            ("maxHeartbeatIntervalMs".into(), Value::Unsigned(1001)),
        ]);
        assert!(validate_b3_profile(&profile).is_err());
        let rollback = Value::Map(vec![
            ("issuedCounter".into(), Value::Unsigned(2)),
            ("expiresCounter".into(), Value::Unsigned(2)),
            ("toDeploymentEpoch".into(), Value::Unsigned(2)),
            ("fromDeploymentEpoch".into(), Value::Unsigned(1)),
            ("toArtifactVersion".into(), Value::Unsigned(1)),
            ("minimumArtifactVersion".into(), Value::Unsigned(1)),
        ]);
        assert!(validate_rollback(&rollback).is_err());
        let mut projection = STATE_PROJECTION_KEYS
            .iter()
            .map(|key| {
                (
                    (*key).into(),
                    if matches!(*key, "scopeKey") {
                        Value::Map(vec![])
                    } else if matches!(*key, "quarantined") {
                        Value::Bool(false)
                    } else if key.ends_with("Digest") {
                        digest()
                    } else {
                        Value::Unsigned(0)
                    },
                )
            })
            .collect::<Vec<_>>();
        projection.push(("generation".into(), Value::Unsigned(1)));
        assert!(exact_keys(&Value::Map(projection), STATE_PROJECTION_KEYS).is_err());
        let malformed_projection = Value::Map(
            STATE_PROJECTION_KEYS
                .iter()
                .map(|key| {
                    (
                        (*key).into(),
                        if *key == "scopeKey" {
                            scope()
                        } else if *key == "quarantined" {
                            Value::Bool(false)
                        } else if key.ends_with("Digest") {
                            Value::Unsigned(7)
                        } else {
                            Value::Unsigned(0)
                        },
                    )
                })
                .collect(),
        );
        assert!(validate_state_projection(&malformed_projection).is_err());
        assert!(
            validate_genesis_epoch(&Value::Map(vec![(
                "trustClass".into(),
                Value::Text("development".into())
            )]))
            .is_err()
        );
        assert!(
            validate_b3_ack(&Value::Map(vec![("sequence".into(), Value::Unsigned(0))])).is_err()
        );
    }
    #[test]
    fn complete_minimal_corpus_has_one_recaptured_fixture_per_schema() {
        let corpus = minimal_p2_corpus().unwrap();
        assert_eq!(corpus.len(), 43);
        let names: BTreeSet<_> = corpus.iter().map(|row| row.0).collect();
        assert_eq!(names.len(), 43);
        for (name, bytes) in corpus {
            assert_eq!(
                capture_p2(&bytes, Some(name)).unwrap().canonical_bytes(),
                bytes
            );
        }
        let (_, ack) = minimal_p2_corpus()
            .unwrap()
            .into_iter()
            .find(|row| row.0 == "B3InvalidationAckV1")
            .unwrap();
        let mut value = decode_canonical(&ack, Limits::MANIFEST).unwrap();
        set_uint(&mut value, "sequence", 0);
        assert!(
            capture_p2(
                &encode_bounded(&value, Limits::MANIFEST).unwrap(),
                Some("B3InvalidationAckV1")
            )
            .is_err()
        );
    }
    #[test]
    fn named_semantic_neuters_refuse_wrong_discriminator_tag_and_landlock_subset() {
        assert!(!canonical_absolute("/."));
        assert!(!canonical_absolute("/.."));
        assert!(!canonical_absolute("/safe/../escape"));
        assert!(canonical_absolute("/safe/path"));
        let zero_signature = Value::Array(vec![Value::Map(vec![
            ("keyId".into(), Value::Text("key.1".into())),
            ("algorithm".into(), Value::Text("ed25519".into())),
            ("keyEpoch".into(), Value::Unsigned(1)),
            ("signature".into(), Value::Bytes(vec![0; 64])),
        ])]);
        validate_signature_rows(&zero_signature, false).unwrap();
        let Value::Array(mut duplicate) = zero_signature.clone() else {
            unreachable!()
        };
        duplicate.push(duplicate[0].clone());
        assert!(validate_signature_rows(&Value::Array(duplicate), false).is_err());
        let mut second = match &zero_signature {
            Value::Array(v) => v[0].clone(),
            _ => unreachable!(),
        };
        if let Value::Map(rows) = &mut second {
            rows.iter_mut().find(|(key, _)| key == "keyId").unwrap().1 =
                Value::Text("key.0".into());
        }
        let Value::Array(mut unsorted) = zero_signature.clone() else {
            unreachable!()
        };
        unsorted.push(second);
        assert!(validate_signature_rows(&Value::Array(unsorted), false).is_err());
        let mut operation = read_operation();
        let Value::Map(rows) = &mut operation else {
            unreachable!()
        };
        rows.iter_mut()
            .find(|(key, _)| key == "operationKind")
            .unwrap()
            .1 = Value::Text("validate-lease".into());
        assert!(operation_digest("B3ReadOperationV1", &operation).is_err());

        let observation = Value::Map(vec![
            (
                "schema".into(),
                Value::Text("keep.native-observation-result".into()),
            ),
            ("version".into(), Value::Unsigned(1)),
            ("resultCode".into(), Value::Text("pass".into())),
            (
                "facts".into(),
                Value::Array(vec![Value::Map(vec![
                    ("factId".into(), Value::Text("fact.1".into())),
                    ("valueType".into(), Value::Text("uint64".into())),
                    ("value".into(), Value::Bool(true)),
                ])]),
            ),
        ]);
        assert!(validate_observation(&observation).is_err());

        let landlock = Value::Map(vec![
            ("minimumAbi".into(), Value::Unsigned(1)),
            (
                "handledFilesystemRights".into(),
                Value::Array(vec![Value::Text("read-file".into())]),
            ),
            ("handledNetworkRights".into(), Value::Array(vec![])),
            ("handledScopeRights".into(), Value::Array(vec![])),
            (
                "rules".into(),
                Value::Array(vec![Value::Map(vec![
                    ("kind".into(), Value::Text("path-beneath".into())),
                    ("path".into(), Value::Text("/usr/lib/keep".into())),
                    (
                        "accessRights".into(),
                        Value::Array(vec![Value::Text("write-file".into())]),
                    ),
                ])]),
            ),
        ]);
        assert!(validate_landlock(&landlock).is_err());
    }
    #[test]
    fn digest_registry_is_type_derived_unique_and_covers_empty_typed_arrays() {
        let registry = digest_registry();
        let paths: BTreeSet<_> = registry.iter().map(|entry| entry.path.as_str()).collect();
        assert_eq!(paths.len(), registry.len());
        assert!(paths.contains("NativeReproducibilityRecordV1.builderProvenanceEnvelopeDigests"));
        assert!(paths.contains("NativePackagePayloadV1.nativeArtifactInventoryDigest"));
        assert!(!registry.iter().any(|entry| entry.semantic_type.is_empty()));
        validate_digest_registry(&registry).unwrap();
        let mut reverse = registry.clone();
        let low = reverse
            .iter()
            .position(|entry| entry.path == "NativePackagePayloadV1.nativeArtifactInventoryDigest")
            .unwrap();
        reverse[low]
            .depends_on
            .push("NativeProvenanceV1.nativePackagePayloadDigest".into());
        assert!(validate_digest_registry(&reverse).is_err());
        let mut missing_nested = registry.clone();
        missing_nested.retain(|entry| entry.path != "NativeSbomV1.packages[].checksum");
        assert_ne!(missing_nested.len(), registry.len());

        super::super::validate_digest_registry(&super::super::NATIVE_V2_DIGEST_REGISTRY).unwrap();
        assert_eq!(super::super::NATIVE_V2_DIGEST_REGISTRY.len(), 80);
        let combined = combined_digest_registry();
        assert_eq!(combined.len(), 80 + registry.len());
        validate_digest_registry(&combined).unwrap();
        for (consumer, producer) in [
            (
                "NativeProvenanceV1.toolchainClosureEnvelopeDigest",
                "NativeToolchainClosureV1.$envelopeDigest",
            ),
            (
                "NativeProvenanceV1.invocationDigest",
                "NativeInvocationV1.$contentDigest",
            ),
            (
                "NativeReproducibilityRecordV1.builderProvenanceEnvelopeDigests",
                "NativeProvenanceV1.$envelopeDigest",
            ),
            (
                "NativeReproducibilityRecordV1.comparisonDigest",
                "NativeComparisonV1.$contentDigest",
            ),
        ] {
            assert!(
                combined
                    .iter()
                    .find(|entry| entry.path == consumer)
                    .unwrap()
                    .depends_on
                    .iter()
                    .any(|dependency| dependency == producer)
            );
        }
        let mut missing_producer = combined.clone();
        missing_producer.retain(|entry| entry.path != "NativeInvocationV1.$contentDigest");
        assert!(validate_digest_registry(&missing_producer).is_err());
        let mut missing_output = combined.clone();
        missing_output.retain(|entry| entry.path != "NativeTimestampV1.$envelopeDigest");
        assert!(validate_digest_registry(&missing_output).is_err());
    }
}
