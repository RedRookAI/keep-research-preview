#![forbid(unsafe_code)]

//! Descriptor-bound observation of the administrator-owned native release graph.
//!
//! This crate deliberately cannot authorize or launch anything. `ObservedDeployment`
//! proves only that exact production-schema bytes were captured from the configured
//! content-addressed location under the exact configured directory identity.

use keep_native_linux_abi::{
    FileIdentity, FilesystemIdentity, PinnedDirectory, SealedFile, seal_data_file_bytes,
};
use keep_native_protocol::{
    Limits, Schema, TrustClass, Value, capture_canonical, decode_canonical, sha256_hex,
};
use std::fmt::{Display, Formatter};
use std::path::Path;

pub const MAXIMUM_DEPLOYMENT_BYTES: u64 = 1_048_576;
pub const MAXIMUM_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAXIMUM_TOTAL_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const DIRECTORY_TYPE: u32 = 0o040000;
const PERMISSION_BITS: u32 = 0o7777;
const REGULAR_TYPE: u32 = 0o100000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredRootIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub mount_id: u64,
    pub filesystem_type: u64,
    pub read_only: bool,
}

impl ConfiguredRootIdentity {
    pub fn from_observed(identity: &FileIdentity, filesystem: &FilesystemIdentity) -> Self {
        Self {
            device: identity.device,
            inode: identity.inode,
            uid: identity.uid,
            gid: identity.gid,
            permissions: identity.mode & PERMISSION_BITS,
            mount_id: filesystem.mount_id,
            filesystem_type: filesystem.filesystem_type,
            read_only: filesystem.read_only,
        }
    }

    pub fn decimal_spec(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            self.device,
            self.inode,
            self.uid,
            self.gid,
            self.permissions,
            self.mount_id,
            self.filesystem_type,
            u8::from(self.read_only)
        )
    }

    pub fn parse_decimal_spec(value: &str) -> Result<Self, ResolverError> {
        let fields = value
            .split(':')
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ResolverError::RootPolicy)?;
        if fields.len() != 8 || fields[7] > 1 {
            return Err(ResolverError::RootPolicy);
        }
        let identity = Self {
            device: fields[0],
            inode: fields[1],
            uid: u32::try_from(fields[2]).map_err(|_| ResolverError::RootPolicy)?,
            gid: u32::try_from(fields[3]).map_err(|_| ResolverError::RootPolicy)?,
            permissions: u32::try_from(fields[4]).map_err(|_| ResolverError::RootPolicy)?,
            mount_id: fields[5],
            filesystem_type: fields[6],
            read_only: fields[7] == 1,
        };
        validate_declared_root_identity(&identity)?;
        if identity.decimal_spec() != value {
            return Err(ResolverError::RootPolicy);
        }
        Ok(identity)
    }
}

#[derive(Debug)]
pub struct ResolverConfiguration {
    authority_root: ConfiguredRoot,
    payload_root: ConfiguredRoot,
}

impl ResolverConfiguration {
    pub fn new(
        authority_root: ConfiguredRoot,
        payload_root: ConfiguredRoot,
    ) -> Result<Self, ResolverError> {
        if authority_root.identity.device == payload_root.identity.device
            && authority_root.identity.inode == payload_root.identity.inode
        {
            return Err(ResolverError::RootPolicy);
        }
        Ok(Self {
            authority_root,
            payload_root,
        })
    }
}

#[derive(Debug)]
pub struct ConfiguredRoot {
    pinned: PinnedDirectory,
    identity: ConfiguredRootIdentity,
}

impl ConfiguredRoot {
    pub fn open(root: &Path, expected: ConfiguredRootIdentity) -> Result<Self, ResolverError> {
        validate_declared_root_identity(&expected)?;
        let pinned = PinnedDirectory::open_mount_root(root).map_err(|_| ResolverError::RootOpen)?;
        let filesystem = pinned
            .filesystem_identity()
            .map_err(|_| ResolverError::RootOpen)?;
        validate_root_policy(pinned.identity(), &filesystem)?;
        validate_root_identity(pinned.identity(), &filesystem, &expected)?;
        Ok(Self {
            pinned,
            identity: expected,
        })
    }

    pub fn identity(&self) -> &ConfiguredRootIdentity {
        &self.identity
    }
}

fn validate_declared_root_identity(identity: &ConfiguredRootIdentity) -> Result<(), ResolverError> {
    if identity.uid != 0
        || identity.gid != 0
        || identity.mount_id == 0
        || identity.filesystem_type == 0
        || !identity.read_only
    {
        return Err(ResolverError::RootPolicy);
    }
    if identity.permissions & 0o222 != 0 || identity.permissions & !PERMISSION_BITS != 0 {
        return Err(ResolverError::RootPolicy);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolverError {
    RequestShape,
    RootOpen,
    RootPolicy,
    RootIdentity,
    ObjectOpen,
    ObjectMetadata,
    ContentAddress,
    CanonicalProductionSchema,
    DeploymentIdentity,
}

impl Display for ResolverError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RequestShape => "resolver request identity is malformed",
            Self::RootOpen => "configured release root could not be pinned",
            Self::RootPolicy => "configured release root policy is invalid",
            Self::RootIdentity => "configured release root identity does not match",
            Self::ObjectOpen => "deployment object could not be captured",
            Self::ObjectMetadata => "deployment object metadata is not immutable root-owned data",
            Self::ContentAddress => "deployment object content address does not match",
            Self::CanonicalProductionSchema => {
                "deployment object is not canonical production schema"
            }
            Self::DeploymentIdentity => "deployment object identity does not match the request",
        })
    }
}

impl std::error::Error for ResolverError {}

#[derive(Debug)]
pub struct ProductionResolver {
    authority_root: PinnedDirectory,
    authority_identity: ConfiguredRootIdentity,
    payload_root: PinnedDirectory,
    payload_identity: ConfiguredRootIdentity,
}

#[derive(Debug)]
pub struct ObservedDeployment {
    sealed: SealedFile,
    canonical_bytes: Vec<u8>,
    deployment_id: String,
    manifest_digest: String,
    transcript_digest: String,
    artifacts: Vec<ObservedArtifact>,
}

#[derive(Debug)]
pub struct ObservedArtifact {
    artifact_id: String,
    kind: String,
    digest: String,
    identity: FileIdentity,
    sealed: SealedFile,
}

impl ObservedDeployment {
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub fn transcript_digest(&self) -> &str {
        &self.transcript_digest
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn sealed_byte_length(&self) -> u64 {
        self.sealed.byte_length()
    }
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }
    pub fn artifact_identities(&self) -> impl Iterator<Item = (&str, &str, &str, u64)> {
        self.artifacts.iter().map(|artifact| {
            (
                artifact.artifact_id.as_str(),
                artifact.kind.as_str(),
                artifact.digest.as_str(),
                artifact.sealed.byte_length(),
            )
        })
    }
}

impl ProductionResolver {
    pub fn open(configuration: ResolverConfiguration) -> Result<Self, ResolverError> {
        let ResolverConfiguration {
            authority_root,
            payload_root,
        } = configuration;
        Ok(Self {
            authority_root: authority_root.pinned,
            authority_identity: authority_root.identity,
            payload_root: payload_root.pinned,
            payload_identity: payload_root.identity,
        })
    }

    pub fn observe_deployment(
        &self,
        deployment_id: &str,
        manifest_digest: &str,
    ) -> Result<ObservedDeployment, ResolverError> {
        if !identifier(deployment_id) || !digest(manifest_digest) {
            return Err(ResolverError::RequestShape);
        }
        let relative = format!("deployments/sha256/{manifest_digest}.cbor");
        let capture = self
            .authority_root
            .capture_regular_file(&relative, MAXIMUM_DEPLOYMENT_BYTES)
            .map_err(|_| ResolverError::ObjectOpen)?;
        validate_leaf(capture.identity())?;
        if sha256_hex(capture.bytes()) != manifest_digest {
            return Err(ResolverError::ContentAddress);
        }
        let document = capture_canonical(capture.bytes(), Limits::MANIFEST, TrustClass::Production)
            .map_err(|_| ResolverError::CanonicalProductionSchema)?;
        if document.schema() != Schema::Deployment {
            return Err(ResolverError::CanonicalProductionSchema);
        }
        let value = decode_canonical(document.canonical_bytes(), Limits::MANIFEST)
            .map_err(|_| ResolverError::CanonicalProductionSchema)?;
        let payload = value
            .field("payload")
            .ok_or(ResolverError::CanonicalProductionSchema)?;
        if payload.field("deploymentId").and_then(Value::as_text) != Some(deployment_id) {
            return Err(ResolverError::DeploymentIdentity);
        }
        let artifacts = capture_required_artifacts(&self.payload_root, payload)?;
        let transcript_digest = transcript_digest(
            &self.authority_identity,
            &self.payload_identity,
            capture.identity(),
            deployment_id,
            manifest_digest,
            &artifacts,
        );
        let canonical_bytes = capture.bytes().to_vec();
        let sealed = seal_data_file_bytes(
            "keep-production-deployment",
            &canonical_bytes,
            MAXIMUM_DEPLOYMENT_BYTES,
            0o400,
        )
        .map_err(|_| ResolverError::ObjectOpen)?;
        Ok(ObservedDeployment {
            sealed,
            canonical_bytes,
            deployment_id: deployment_id.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
            transcript_digest,
            artifacts,
        })
    }
}

fn capture_required_artifacts(
    root: &PinnedDirectory,
    payload: &Value,
) -> Result<Vec<ObservedArtifact>, ResolverError> {
    let rows = match payload.field("artifacts") {
        Some(Value::Array(rows)) => rows,
        _ => return Err(ResolverError::CanonicalProductionSchema),
    };
    let mut artifacts = Vec::with_capacity(rows.len());
    let mut total_bytes = 0u64;
    for row in rows {
        let required_kind = row
            .field("kind")
            .and_then(Value::as_text)
            .ok_or(ResolverError::CanonicalProductionSchema)?;
        if !matches!(
            required_kind,
            "helper" | "trampoline" | "prober" | "provisioner" | "role"
        ) {
            return Err(ResolverError::CanonicalProductionSchema);
        }
        let artifact_id = row
            .field("artifactId")
            .and_then(Value::as_text)
            .ok_or(ResolverError::CanonicalProductionSchema)?;
        let artifact_digest = row
            .field("digest")
            .and_then(Value::as_text)
            .ok_or(ResolverError::CanonicalProductionSchema)?;
        let relative = format!("artifacts/sha256/{artifact_digest}");
        let capture = root
            .capture_regular_file(&relative, MAXIMUM_EXECUTABLE_BYTES)
            .map_err(|_| ResolverError::ObjectOpen)?;
        validate_executable_leaf(capture.identity())?;
        if sha256_hex(capture.bytes()) != artifact_digest {
            return Err(ResolverError::ContentAddress);
        }
        total_bytes = admit_total_artifact_bytes(total_bytes, capture.identity().size)?;
        let sealed = seal_data_file_bytes(
            &format!("keep-production-{required_kind}"),
            capture.bytes(),
            MAXIMUM_EXECUTABLE_BYTES,
            0o400,
        )
        .map_err(|_| ResolverError::ObjectOpen)?;
        artifacts.push(ObservedArtifact {
            artifact_id: artifact_id.to_owned(),
            kind: required_kind.to_owned(),
            digest: artifact_digest.to_owned(),
            identity: capture.identity().clone(),
            sealed,
        });
    }
    Ok(artifacts)
}

fn admit_total_artifact_bytes(current: u64, additional: u64) -> Result<u64, ResolverError> {
    current
        .checked_add(additional)
        .filter(|total| *total <= MAXIMUM_TOTAL_ARTIFACT_BYTES)
        .ok_or(ResolverError::ObjectOpen)
}

fn validate_root_policy(
    actual: &FileIdentity,
    filesystem: &FilesystemIdentity,
) -> Result<(), ResolverError> {
    if actual.mode & libc_mode_type_mask() != DIRECTORY_TYPE
        || actual.uid != 0
        || actual.gid != 0
        || actual.mode & 0o222 != 0
        || !filesystem.read_only
    {
        return Err(ResolverError::RootPolicy);
    }
    Ok(())
}

fn validate_root_identity(
    actual: &FileIdentity,
    filesystem: &FilesystemIdentity,
    expected: &ConfiguredRootIdentity,
) -> Result<(), ResolverError> {
    if actual.device != expected.device
        || actual.inode != expected.inode
        || actual.uid != expected.uid
        || actual.gid != expected.gid
        || actual.mode & PERMISSION_BITS != expected.permissions
        || filesystem.mount_id != expected.mount_id
        || filesystem.filesystem_type != expected.filesystem_type
        || filesystem.read_only != expected.read_only
    {
        return Err(ResolverError::RootIdentity);
    }
    Ok(())
}

fn validate_leaf(identity: &FileIdentity) -> Result<(), ResolverError> {
    if identity.mode & libc_mode_type_mask() != REGULAR_TYPE
        || identity.uid != 0
        || identity.gid != 0
        || identity.mode & PERMISSION_BITS != 0o444
        || identity.links != 1
    {
        return Err(ResolverError::ObjectMetadata);
    }
    Ok(())
}

fn validate_executable_leaf(identity: &FileIdentity) -> Result<(), ResolverError> {
    if identity.mode & libc_mode_type_mask() != REGULAR_TYPE
        || identity.uid != 0
        || identity.gid != 0
        || identity.mode & PERMISSION_BITS != 0o555
        || identity.links != 1
    {
        return Err(ResolverError::ObjectMetadata);
    }
    Ok(())
}

const fn libc_mode_type_mask() -> u32 {
    0o170000
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn transcript_digest(
    authority_root: &ConfiguredRootIdentity,
    payload_root: &ConfiguredRootIdentity,
    leaf: &FileIdentity,
    deployment_id: &str,
    manifest_digest: &str,
    artifacts: &[ObservedArtifact],
) -> String {
    let mut bytes = b"keep.native-production-resolution-observation/v2\0".to_vec();
    for value in [authority_root, payload_root]
        .into_iter()
        .flat_map(|root| {
            [
                root.device,
                root.inode,
                root.mount_id,
                root.filesystem_type,
                u64::from(root.uid),
                u64::from(root.gid),
                u64::from(root.permissions),
                u64::from(root.read_only),
            ]
        })
        .chain([
            leaf.device,
            leaf.inode,
            u64::from(leaf.uid),
            u64::from(leaf.gid),
            u64::from(leaf.mode),
            leaf.size,
        ])
    {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&(deployment_id.len() as u64).to_be_bytes());
    bytes.extend_from_slice(deployment_id.as_bytes());
    bytes.extend_from_slice(manifest_digest.as_bytes());
    for artifact in artifacts {
        for value in [&artifact.artifact_id, &artifact.kind, &artifact.digest] {
            bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        for value in [
            artifact.identity.device,
            artifact.identity.inode,
            u64::from(artifact.identity.uid),
            u64::from(artifact.identity.gid),
            u64::from(artifact.identity.mode),
            artifact.identity.links,
            artifact.identity.size,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&artifact.sealed.byte_length().to_be_bytes());
    }
    sha256_hex(&bytes)
}

/// Enrollment-only helper for the executable test probe. The unique mount ID is boot-scoped:
/// production resolution must receive a freshly enrolled identity from the trusted boot path,
/// then use `ConfiguredRoot::open` without re-enrolling or reopening the pathname.
pub fn enroll_configured_root_for_probe(path: &Path) -> Result<ConfiguredRoot, ResolverError> {
    let root = PinnedDirectory::open_mount_root(path).map_err(|_| ResolverError::RootOpen)?;
    let filesystem = root
        .filesystem_identity()
        .map_err(|_| ResolverError::RootOpen)?;
    let identity = ConfiguredRootIdentity::from_observed(root.identity(), &filesystem);
    validate_root_policy(root.identity(), &filesystem)?;
    Ok(ConfiguredRoot {
        pinned: root,
        identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keep_native_linux_abi::REQUIRED_DATA_MEMFD_SEALS;
    use std::fs::{Permissions, create_dir_all, set_permissions, write};
    use std::io::Read;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn descriptor_count() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    fn scratch() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "keep-production-resolver-{}-{nonce}",
            std::process::id()
        ));
        create_dir_all(root.join("artifacts/sha256")).unwrap();
        root
    }

    fn artifact_payload(rows: Vec<Value>) -> Value {
        Value::Map(vec![("artifacts".into(), Value::Array(rows))])
    }

    fn artifact_row(id: &str, kind: &str, digest: &str) -> Value {
        Value::Map(vec![
            ("artifactId".into(), Value::Text(id.into())),
            ("kind".into(), Value::Text(kind.into())),
            ("digest".into(), Value::Text(digest.into())),
        ])
    }

    #[test]
    fn request_identifiers_are_closed() {
        let _lock = TEST_LOCK.lock().unwrap();
        assert!(identifier("production.deploy-1"));
        assert!(!identifier("../deploy"));
        assert!(!identifier("deploy/path"));
        assert!(digest(&"ab".repeat(32)));
        assert!(!digest(&"AB".repeat(32)));
    }

    #[test]
    fn configuration_refuses_writable_or_non_root_policy() {
        let _lock = TEST_LOCK.lock().unwrap();
        let identity = ConfiguredRootIdentity {
            device: 1,
            inode: 2,
            uid: 0,
            gid: 0,
            permissions: 0o755,
            mount_id: 3,
            filesystem_type: 4,
            read_only: true,
        };
        assert_eq!(
            validate_declared_root_identity(&identity).unwrap_err(),
            ResolverError::RootPolicy
        );
        let identity = ConfiguredRootIdentity {
            device: 1,
            inode: 2,
            uid: 1,
            gid: 0,
            permissions: 0o555,
            mount_id: 3,
            filesystem_type: 4,
            read_only: true,
        };
        assert_eq!(
            validate_declared_root_identity(&identity).unwrap_err(),
            ResolverError::RootPolicy
        );
    }

    #[test]
    fn aggregate_artifact_bytes_are_bounded_without_overflow() {
        let _lock = TEST_LOCK.lock().unwrap();
        assert_eq!(
            admit_total_artifact_bytes(MAXIMUM_TOTAL_ARTIFACT_BYTES - 1, 1).unwrap(),
            MAXIMUM_TOTAL_ARTIFACT_BYTES
        );
        assert_eq!(
            admit_total_artifact_bytes(MAXIMUM_TOTAL_ARTIFACT_BYTES, 1).unwrap_err(),
            ResolverError::ObjectOpen
        );
        assert_eq!(
            admit_total_artifact_bytes(u64::MAX, 1).unwrap_err(),
            ResolverError::ObjectOpen
        );
    }

    #[test]
    fn required_executables_are_content_addressed_and_sealed() {
        let _lock = TEST_LOCK.lock().unwrap();
        let root = scratch();
        let mut rows = Vec::new();
        for (id, kind, bytes) in [
            ("keep.helper", "helper", b"helper".as_slice()),
            ("keep.trampoline", "trampoline", b"trampoline".as_slice()),
            ("keep.prober", "prober", b"prober".as_slice()),
        ] {
            let digest = sha256_hex(bytes);
            let path = root.join(format!("artifacts/sha256/{digest}"));
            write(&path, bytes).unwrap();
            set_permissions(path, Permissions::from_mode(0o555)).unwrap();
            rows.push(artifact_row(id, kind, &digest));
        }
        let pinned = PinnedDirectory::open(&root).unwrap();
        let artifacts = capture_required_artifacts(&pinned, &artifact_payload(rows)).unwrap();
        assert_eq!(artifacts.len(), 3);
        assert!(
            artifacts
                .iter()
                .all(|artifact| artifact.sealed.seals().unwrap() == REQUIRED_DATA_MEMFD_SEALS)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn required_executables_refuse_wrong_mode_symlink_and_digest() {
        let _lock = TEST_LOCK.lock().unwrap();
        for attack in ["mode", "symlink", "digest"] {
            let root = scratch();
            let mut rows = Vec::new();
            for (id, kind) in [
                ("keep.helper", "helper"),
                ("keep.trampoline", "trampoline"),
                ("keep.prober", "prober"),
            ] {
                let bytes = kind.as_bytes();
                let digest = sha256_hex(bytes);
                let path = root.join(format!("artifacts/sha256/{digest}"));
                if attack == "symlink" && kind == "helper" {
                    let target = root.join("outside");
                    write(&target, bytes).unwrap();
                    symlink(&target, &path).unwrap();
                } else {
                    write(
                        &path,
                        if attack == "digest" && kind == "helper" {
                            b"mutant"
                        } else {
                            bytes
                        },
                    )
                    .unwrap();
                    set_permissions(
                        &path,
                        Permissions::from_mode(if attack == "mode" && kind == "helper" {
                            0o755
                        } else {
                            0o555
                        }),
                    )
                    .unwrap();
                }
                rows.push(artifact_row(id, kind, &digest));
            }
            let pinned = PinnedDirectory::open(&root).unwrap();
            assert!(
                capture_required_artifacts(&pinned, &artifact_payload(rows)).is_err(),
                "accepted {attack}"
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn sealed_executables_survive_live_inode_mutation_and_drop_without_leaks() {
        let _lock = TEST_LOCK.lock().unwrap();
        let baseline = descriptor_count();
        let root = scratch();
        let mut rows = Vec::new();
        let mut paths = Vec::new();
        for (id, kind) in [
            ("helper", "helper"),
            ("trampoline", "trampoline"),
            ("prober", "prober"),
        ] {
            let bytes = kind.as_bytes();
            let digest = sha256_hex(bytes);
            let path = root.join(format!("artifacts/sha256/{digest}"));
            write(&path, bytes).unwrap();
            set_permissions(&path, Permissions::from_mode(0o555)).unwrap();
            paths.push((path, bytes.to_vec()));
            rows.push(artifact_row(id, kind, &digest));
        }
        let pinned = PinnedDirectory::open(&root).unwrap();
        let artifacts = capture_required_artifacts(&pinned, &artifact_payload(rows)).unwrap();
        let sealed_descriptors = artifacts
            .iter()
            .map(|artifact| artifact.sealed.descriptor())
            .collect::<Vec<_>>();
        for (path, _) in &paths {
            set_permissions(path, Permissions::from_mode(0o755)).unwrap();
            write(path, b"live-mutant").unwrap();
        }
        for (artifact, (_, expected)) in artifacts.iter().zip(paths.iter()) {
            let mut recaptured = Vec::new();
            std::fs::File::open(format!("/proc/self/fd/{}", artifact.sealed.descriptor()))
                .unwrap()
                .read_to_end(&mut recaptured)
                .unwrap();
            assert_eq!(&recaptured, expected);
        }
        drop(artifacts);
        drop(pinned);
        std::fs::remove_dir_all(root).unwrap();
        for descriptor in sealed_descriptors {
            assert!(std::fs::metadata(format!("/proc/self/fd/{descriptor}")).is_err());
        }
        assert_eq!(descriptor_count(), baseline);
    }
}
