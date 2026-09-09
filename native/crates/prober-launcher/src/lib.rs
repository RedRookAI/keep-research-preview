#![forbid(unsafe_code)]

//! Mechanically non-authorizing lifecycle core for one native PROBER launch.
//!
//! This crate intentionally has no conversion from `ObservedDeployment`, no production
//! constructor, and no authority/evidence/role-handle output. The candidate-probe feature
//! exists only to exercise fixed repository-owned test bytes until P2-D2/B0/B3 are admitted.

use std::fmt::{Display, Formatter};
#[cfg(any(test, feature = "candidate-probe"))]
use std::fs::File;
use std::io;
#[cfg(any(test, feature = "candidate-probe"))]
use std::path::Path;
#[cfg(any(test, feature = "candidate-probe"))]
use std::process::{Child, Command, ExitStatus, Stdio};
#[cfg(any(test, feature = "candidate-probe"))]
use std::thread::sleep;
use std::time::{Duration, Instant};

#[cfg(any(test, feature = "candidate-probe"))]
use keep_native_linux_abi::{ProcessIdentity, reviewed_landlock_policy};
use keep_native_linux_abi::{fill_random, zeroize};
#[cfg(feature = "candidate-probe")]
use keep_native_protocol::Sha256State;
use keep_native_protocol::sha256;

pub const GUEST_VCPU_COUNT: u8 = 1;
pub const GUEST_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
pub const HOST_MEMORY_BYTES: u64 = GUEST_MEMORY_BYTES + 256 * 1024 * 1024;
pub const MAXIMUM_PIDS: u64 = 128;
pub const MAXIMUM_OUTPUT_BYTES: u64 = 1024 * 1024;
pub const MAXIMUM_LAUNCH_MILLISECONDS: u64 = 120_000;
pub const MAXIMUM_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAXIMUM_OPEN_FILES: u64 = 1024;
pub const CGROUP_CPU_MAX: &str = "100000 100000";
pub const CGROUP_IO_WEIGHT: &str = "default 100";
pub const CGROUP_IO_WEIGHT_WRITE: &str = "100";
#[cfg(feature = "candidate-probe")]
const LANDLOCK_DENIED_CANARY_BYTES: &[u8] =
    b"Landlock must deny mutation despite DAC write permission.\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateRefusal {
    InvalidAttemptId,
    DeadlineOutOfRange,
    DeadlineExpired,
    CgroupValueMalformed,
    CgroupLimitMismatch,
    CgroupStillPopulated,
    CgroupHasDescendants,
    OutputLimitExceeded,
    DirectProcessFailed,
    GuestResultMalformed,
    GuestResultHeaderInvalid,
    GuestResultTruncated,
    GuestResultDigestMismatch,
    GuestResultAmbiguous,
    GuestResultNonceInvalid,
    GuestResultEnvelopeTooLarge,
    GuestResultHeaderAbsent,
    GuestResultHeaderDuplicate,
    GuestResultPreambleTooLarge,
    GuestResultDecimalInvalid,
    GuestResultUtf8Invalid,
    GuestResultAuthenticationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateGuestResult {
    pub attempt_nonce: String,
    pub exit_code: u8,
    pub stdout: String,
    pub stderr: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}

pub struct CandidateFixtureSecrets {
    pub attempt_id: CandidateAttemptId,
    pub result_nonce: String,
    pub authentication_key: [u8; 32],
    pub authentication_ipad: [u8; 64],
    pub authentication_opad: [u8; 64],
}

impl Drop for CandidateFixtureSecrets {
    fn drop(&mut self) {
        zeroize(&mut self.authentication_key);
        zeroize(&mut self.authentication_ipad);
        zeroize(&mut self.authentication_opad);
        self.result_nonce.clear();
    }
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("String writes cannot fail");
    }
    result
}

pub fn mint_candidate_fixture_secrets() -> io::Result<CandidateFixtureSecrets> {
    let mut random = [0u8; 64];
    fill_random(&mut random)?;
    let attempt_id = CandidateAttemptId::from_nonce_hex(&bytes_hex(&random[..16]))
        .map_err(|_| io::Error::other("kernel random attempt identity was malformed"))?;
    let result_nonce = bytes_hex(&random[16..32]);
    let mut authentication_key = [0u8; 32];
    authentication_key.copy_from_slice(&random[32..]);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (index, byte) in authentication_key.iter().enumerate() {
        ipad[index] ^= byte;
        opad[index] ^= byte;
    }
    zeroize(&mut random);
    Ok(CandidateFixtureSecrets {
        attempt_id,
        result_nonce,
        authentication_key,
        authentication_ipad: ipad,
        authentication_opad: opad,
    })
}

pub const CANDIDATE_REQUEST_SCRIPT: &[u8] =
    b"#!/bin/sh\nset -eu\nprintf 'ok 1 - native-prober-candidate\\n'\n";
const SECCOMP_DENIAL_CANARY_SOURCE: &[u8] = b"{\"vmm\":{\"default_action\":\"trap\",\"filter_action\":\"allow\",\"filter\":[{\"syscall\":\"exit\"},{\"syscall\":\"exit_group\"}]},\"api\":{\"default_action\":\"trap\",\"filter_action\":\"allow\",\"filter\":[{\"syscall\":\"exit\"},{\"syscall\":\"exit_group\"}]},\"vcpu\":{\"default_action\":\"trap\",\"filter_action\":\"allow\",\"filter\":[{\"syscall\":\"exit\"},{\"syscall\":\"exit_group\"}]}}\n";

pub fn fixed_firecracker_config() -> Vec<u8> {
    format!(
        concat!(
            "{{\"boot-source\":{{\"kernel_image_path\":\"/vmlinux\",",
            "\"boot_args\":\"init=/keep-init ro console=ttyS0 reboot=k panic=1 pci=off quiet 8250.nr_uarts=1 keep.max_output={} keep.fsize={} keep.pids={}\"}},",
            "\"drives\":[{{\"drive_id\":\"rootfs\",\"path_on_host\":\"/rootfs.ext4\",\"is_root_device\":true,\"is_read_only\":true}},",
            "{{\"drive_id\":\"project\",\"path_on_host\":\"/project.ext4\",\"is_root_device\":false,\"is_read_only\":false}}],",
            "\"machine-config\":{{\"vcpu_count\":{},\"mem_size_mib\":{}}}}}\n"
        ),
        MAXIMUM_OUTPUT_BYTES,
        MAXIMUM_FILE_BYTES,
        MAXIMUM_PIDS,
        GUEST_VCPU_COUNT,
        GUEST_MEMORY_BYTES / (1024 * 1024),
    )
    .into_bytes()
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn exact_decimal(value: &str, maximum: u64) -> Result<u64, CandidateRefusal> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || value.len() > 10
        || value.bytes().any(|byte| !byte.is_ascii_digit())
    {
        return Err(CandidateRefusal::GuestResultDecimalInvalid);
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|number| *number <= maximum)
        .ok_or(CandidateRefusal::GuestResultDecimalInvalid)
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(64);
    for byte in sha256(bytes) {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("String writes cannot fail");
    }
    result
}

fn hmac_sha256(key: &[u8; 32], messages: &[&[u8]]) -> [u8; 32] {
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner[index] ^= byte;
        outer[index] ^= byte;
    }
    let inner_length = 64 + messages.iter().map(|message| message.len()).sum::<usize>();
    let mut inner_input = Vec::with_capacity(inner_length);
    inner_input.extend_from_slice(&inner);
    for message in messages {
        inner_input.extend_from_slice(message);
    }
    let inner_digest = sha256(&inner_input);
    let mut outer_input = Vec::with_capacity(96);
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_digest);
    sha256(&outer_input)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], CandidateRefusal> {
    if !lowercase_hex(value, 64) {
        return Err(CandidateRefusal::GuestResultHeaderInvalid);
    }
    let mut result = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => 0,
        };
        result[index] = nibble(pair[0]) << 4 | nibble(pair[1]);
    }
    Ok(result)
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

pub fn parse_candidate_guest_result(
    serial: &[u8],
    expected_nonce: &str,
    authentication_key: &[u8; 32],
) -> Result<CandidateGuestResult, CandidateRefusal> {
    const HEADER: &[u8] = b"KEEP_RESULT_V1 ";
    const END: &[u8] = b"KEEP_RESULT_END_V1";
    const MAXIMUM_PREAMBLE: usize = 256 * 1024;
    const MAXIMUM_POSTAMBLE: usize = 64 * 1024;
    const MAXIMUM_ENVELOPE: usize = 2 * 1024 * 1024 + 4096;
    if !lowercase_hex(expected_nonce, 32) {
        return Err(CandidateRefusal::GuestResultNonceInvalid);
    }
    if serial.len() > MAXIMUM_PREAMBLE + MAXIMUM_ENVELOPE + MAXIMUM_POSTAMBLE {
        return Err(CandidateRefusal::GuestResultEnvelopeTooLarge);
    }
    let mut needle = HEADER.to_vec();
    needle.extend_from_slice(expected_nonce.as_bytes());
    needle.push(b' ');
    let starts = serial
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| (window == needle).then_some(index))
        .collect::<Vec<_>>();
    if starts.is_empty() {
        return Err(CandidateRefusal::GuestResultHeaderAbsent);
    }
    if starts.len() != 1 {
        return Err(CandidateRefusal::GuestResultHeaderDuplicate);
    }
    if starts[0] > MAXIMUM_PREAMBLE {
        return Err(CandidateRefusal::GuestResultPreambleTooLarge);
    }
    let start = starts[0];
    let line_end = serial[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| start + offset)
        .filter(|end| end - start <= 512)
        .ok_or(CandidateRefusal::GuestResultHeaderInvalid)?;
    let header = std::str::from_utf8(&serial[start..line_end])
        .map_err(|_| CandidateRefusal::GuestResultUtf8Invalid)?;
    let fields = header.split(' ').collect::<Vec<_>>();
    if fields.len() != 8 || fields[0] != "KEEP_RESULT_V1" || fields[1] != expected_nonce {
        return Err(CandidateRefusal::GuestResultHeaderInvalid);
    }
    let exit_code = exact_decimal(fields[2], 255)? as u8;
    let stdout_length = exact_decimal(fields[3], MAXIMUM_OUTPUT_BYTES)? as usize;
    let stderr_length = exact_decimal(fields[4], MAXIMUM_OUTPUT_BYTES)? as usize;
    if !lowercase_hex(fields[5], 64) || !lowercase_hex(fields[6], 64) {
        return Err(CandidateRefusal::GuestResultHeaderInvalid);
    }
    let supplied_mac = decode_hex_32(fields[7])?;
    let payload_start = line_end + 1;
    let payload_end = payload_start
        .checked_add(stdout_length)
        .and_then(|end| end.checked_add(stderr_length))
        .ok_or(CandidateRefusal::GuestResultTruncated)?;
    let end = format!(
        "\n{} {}\n",
        std::str::from_utf8(END).expect("ASCII"),
        expected_nonce
    );
    if payload_end + end.len() > serial.len()
        || payload_end + end.len() - start > MAXIMUM_ENVELOPE
        || &serial[payload_end..payload_end + end.len()] != end.as_bytes()
    {
        return Err(CandidateRefusal::GuestResultTruncated);
    }
    let stdout = &serial[payload_start..payload_start + stdout_length];
    let stderr = &serial[payload_start + stdout_length..payload_end];
    if hex_digest(stdout) != fields[5] || hex_digest(stderr) != fields[6] {
        return Err(CandidateRefusal::GuestResultDigestMismatch);
    }
    let unsigned_header = format!(
        "KEEP_RESULT_V1 {expected_nonce} {exit_code} {stdout_length} {stderr_length} {} {}\n",
        fields[5], fields[6]
    );
    let expected_mac = hmac_sha256(
        authentication_key,
        &[
            b"keep.microvm-result-auth/v1\0",
            unsigned_header.as_bytes(),
            stdout,
            stderr,
            end.as_bytes(),
        ],
    );
    if !constant_time_equal(&supplied_mac, &expected_mac) {
        return Err(CandidateRefusal::GuestResultAuthenticationFailed);
    }
    let postamble = &serial[payload_end + end.len()..];
    if postamble.len() > MAXIMUM_POSTAMBLE
        || postamble
            .windows(HEADER.len())
            .any(|window| window == HEADER)
        || postamble.windows(END.len()).any(|window| window == END)
    {
        return Err(CandidateRefusal::GuestResultAmbiguous);
    }
    Ok(CandidateGuestResult {
        attempt_nonce: expected_nonce.to_owned(),
        exit_code,
        stdout: std::str::from_utf8(stdout)
            .map_err(|_| CandidateRefusal::GuestResultUtf8Invalid)?
            .to_owned(),
        stderr: std::str::from_utf8(stderr)
            .map_err(|_| CandidateRefusal::GuestResultUtf8Invalid)?
            .to_owned(),
        stdout_sha256: fields[5].to_owned(),
        stderr_sha256: fields[6].to_owned(),
    })
}

#[cfg(any(test, feature = "candidate-probe"))]
#[derive(Debug)]
struct CandidateDirectProcess {
    child: Option<Child>,
    identity: ProcessIdentity,
    stdout: File,
    stderr: File,
}

#[cfg(any(test, feature = "candidate-probe"))]
#[derive(Debug)]
struct ReapedCandidateProcess {
    status: ExitStatus,
    stdout_bytes: u64,
    stderr_bytes: u64,
}

#[cfg(any(test, feature = "candidate-probe"))]
impl CandidateDirectProcess {
    fn spawn(
        executable: &Path,
        arguments: &[String],
        environment: &[(&str, &str)],
        working_directory: &Path,
        stdout: File,
        stderr: File,
    ) -> io::Result<Self> {
        let mut command = Command::new(executable);
        command
            .args(arguments)
            .current_dir(working_directory)
            .env_clear()
            .envs(environment.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout.try_clone()?))
            .stderr(Stdio::from(stderr.try_clone()?));
        let mut child = command.spawn()?;
        let identity = match ProcessIdentity::open(child.id()) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        Ok(Self {
            child: Some(child),
            identity,
            stdout,
            stderr,
        })
    }

    fn wait_bounded(
        mut self,
        deadline: &CandidateDeadline,
        maximum_output_bytes: u64,
    ) -> Result<ReapedCandidateProcess, CandidateRefusal> {
        loop {
            let stdout_bytes = self
                .stdout
                .metadata()
                .map_err(|_| CandidateRefusal::DirectProcessFailed)?
                .len();
            let stderr_bytes = self
                .stderr
                .metadata()
                .map_err(|_| CandidateRefusal::DirectProcessFailed)?
                .len();
            if stdout_bytes
                .checked_add(stderr_bytes)
                .filter(|total| *total <= maximum_output_bytes)
                .is_none()
            {
                let _ = self.identity.kill();
                let _ = self.child.as_mut().expect("owned child").wait();
                self.child = None;
                return Err(CandidateRefusal::OutputLimitExceeded);
            }
            match self
                .child
                .as_mut()
                .expect("owned child")
                .try_wait()
                .map_err(|_| CandidateRefusal::DirectProcessFailed)?
            {
                Some(status) => {
                    let stdout_bytes = self
                        .stdout
                        .metadata()
                        .map_err(|_| CandidateRefusal::DirectProcessFailed)?
                        .len();
                    let stderr_bytes = self
                        .stderr
                        .metadata()
                        .map_err(|_| CandidateRefusal::DirectProcessFailed)?
                        .len();
                    if stdout_bytes
                        .checked_add(stderr_bytes)
                        .filter(|total| *total <= maximum_output_bytes)
                        .is_none()
                    {
                        let _ = self.child.as_mut().expect("owned child").wait();
                        self.child = None;
                        return Err(CandidateRefusal::OutputLimitExceeded);
                    }
                    self.child = None;
                    return Ok(ReapedCandidateProcess {
                        status,
                        stdout_bytes,
                        stderr_bytes,
                    });
                }
                None => {
                    let remaining = match deadline.remaining() {
                        Ok(remaining) => remaining,
                        Err(error) => {
                            let _ = self.identity.kill();
                            let _ = self.child.as_mut().expect("owned child").wait();
                            self.child = None;
                            return Err(error);
                        }
                    };
                    sleep(remaining.min(Duration::from_millis(5)));
                }
            }
        }
    }
}

#[cfg(any(test, feature = "candidate-probe"))]
impl Drop for CandidateDirectProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = self.identity.kill();
            let _ = child.wait();
            self.child = None;
        }
    }
}

impl Display for CandidateRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native PROBER launch candidate refused: {self:?}"
        )
    }
}

impl std::error::Error for CandidateRefusal {}

/// A monotonic, non-extendable transaction deadline. Wall-clock changes cannot grant time.
#[derive(Clone, Debug)]
pub struct CandidateDeadline {
    started: Instant,
    limit: Duration,
}

impl CandidateDeadline {
    pub fn start(milliseconds: u64) -> Result<Self, CandidateRefusal> {
        if milliseconds == 0 || milliseconds > MAXIMUM_LAUNCH_MILLISECONDS {
            return Err(CandidateRefusal::DeadlineOutOfRange);
        }
        Ok(Self {
            started: Instant::now(),
            limit: Duration::from_millis(milliseconds),
        })
    }

    pub fn remaining(&self) -> Result<Duration, CandidateRefusal> {
        self.limit
            .checked_sub(self.started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(CandidateRefusal::DeadlineExpired)
    }
}

/// Closed attempt identity used for jail and cgroup names, never a caller path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateAttemptId(String);

impl CandidateAttemptId {
    pub fn from_nonce_hex(nonce: &str) -> Result<Self, CandidateRefusal> {
        if nonce.len() != 32
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CandidateRefusal::InvalidAttemptId);
        }
        Ok(Self(format!("keep-{nonce}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateCgroupLimits {
    pub memory_max: u64,
    pub memory_swap_max: u64,
    pub pids_max: u64,
    pub cpu_max: &'static str,
    pub io_weight: &'static str,
}

impl CandidateCgroupLimits {
    pub fn fixed() -> Self {
        Self {
            memory_max: HOST_MEMORY_BYTES,
            memory_swap_max: 0,
            pids_max: MAXIMUM_PIDS,
            cpu_max: CGROUP_CPU_MAX,
            io_weight: CGROUP_IO_WEIGHT,
        }
    }

    pub fn verify(&self, observed: &CandidateCgroupObservation) -> Result<(), CandidateRefusal> {
        if observed.memory_max != self.memory_max
            || observed.memory_swap_max != self.memory_swap_max
            || observed.pids_max != self.pids_max
            || observed.cpu_max != self.cpu_max
            || observed.io_weight != self.io_weight
        {
            return Err(CandidateRefusal::CgroupLimitMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateCgroupObservation {
    pub memory_max: u64,
    pub memory_swap_max: u64,
    pub pids_max: u64,
    pub cpu_max: String,
    pub io_weight: String,
    pub populated: bool,
    pub descendant_directories: usize,
}

impl CandidateCgroupObservation {
    pub fn parse(
        memory_max: &str,
        memory_swap_max: &str,
        pids_max: &str,
        cpu_max: &str,
        io_weight: &str,
        cgroup_events: &str,
        descendant_directories: usize,
    ) -> Result<Self, CandidateRefusal> {
        fn bounded_number(value: &str) -> Result<u64, CandidateRefusal> {
            if value.is_empty()
                || value.starts_with('+')
                || (value.len() > 1 && value.starts_with('0'))
                || value.bytes().any(|byte| !byte.is_ascii_digit())
            {
                return Err(CandidateRefusal::CgroupValueMalformed);
            }
            value
                .parse::<u64>()
                .map_err(|_| CandidateRefusal::CgroupValueMalformed)
        }
        let mut populated = None;
        for line in cgroup_events.lines() {
            let mut fields = line.split(' ');
            match (fields.next(), fields.next(), fields.next()) {
                (Some("populated"), Some("0"), None) => populated = Some(false),
                (Some("populated"), Some("1"), None) => populated = Some(true),
                (Some(_), Some(_), None) => {}
                _ => return Err(CandidateRefusal::CgroupValueMalformed),
            }
        }
        Ok(Self {
            memory_max: bounded_number(memory_max)?,
            memory_swap_max: bounded_number(memory_swap_max)?,
            pids_max: bounded_number(pids_max)?,
            cpu_max: cpu_max.to_owned(),
            io_weight: io_weight.to_owned(),
            populated: populated.ok_or(CandidateRefusal::CgroupValueMalformed)?,
            descendant_directories,
        })
    }

    pub fn verify_empty(&self) -> Result<(), CandidateRefusal> {
        if self.populated {
            return Err(CandidateRefusal::CgroupStillPopulated);
        }
        if self.descendant_directories != 0 {
            return Err(CandidateRefusal::CgroupHasDescendants);
        }
        Ok(())
    }
}

/// The only jailer arguments admitted by the fixed candidate. No caller string enters this list.
pub fn fixed_jailer_arguments(attempt: &CandidateAttemptId, uid: u32) -> Vec<String> {
    vec![
        "--id".into(),
        attempt.as_str().into(),
        "--uid".into(),
        uid.to_string(),
        "--gid".into(),
        uid.to_string(),
        "--new-pid-ns".into(),
        "--cgroup-version".into(),
        "2".into(),
        "--parent-cgroup".into(),
        "keep".into(),
        "--cgroup".into(),
        format!("memory.max={HOST_MEMORY_BYTES}"),
        "--cgroup".into(),
        "memory.swap.max=0".into(),
        "--cgroup".into(),
        format!("pids.max={MAXIMUM_PIDS}"),
        "--cgroup".into(),
        format!("cpu.max={CGROUP_CPU_MAX}"),
        "--cgroup".into(),
        format!("io.weight={CGROUP_IO_WEIGHT_WRITE}"),
        "--resource-limit".into(),
        format!("fsize={MAXIMUM_FILE_BYTES}"),
        "--resource-limit".into(),
        format!("no-file={MAXIMUM_OPEN_FILES}"),
        "--".into(),
        "--no-api".into(),
        "--config-file".into(),
        "/config.json".into(),
        "--seccomp-filter".into(),
        "/seccomp.bpf".into(),
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidatePhase {
    Prepared,
    Spawned,
    GuestResultCaptured,
    DirectProcessReaped,
    DescendantsEmpty,
    ResidueRemoved,
    Complete,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateEvent {
    Spawned,
    GuestResultCaptured,
    DirectProcessReaped,
    DescendantsEmpty,
    ResidueRemoved,
    Complete,
    Abort,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateLifecycle {
    phase: CandidatePhase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateLifecycleError {
    phase: CandidatePhase,
    event: CandidateEvent,
}

impl Display for CandidateLifecycleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "candidate launch transition {:?} is invalid from {:?}",
            self.event, self.phase
        )
    }
}

impl std::error::Error for CandidateLifecycleError {}

impl CandidateLifecycle {
    pub fn prepared() -> Self {
        Self {
            phase: CandidatePhase::Prepared,
        }
    }

    pub fn phase(&self) -> CandidatePhase {
        self.phase
    }

    pub fn advance(&mut self, event: CandidateEvent) -> Result<(), CandidateLifecycleError> {
        let next = match (self.phase, event) {
            (_, CandidateEvent::Abort)
                if !matches!(
                    self.phase,
                    CandidatePhase::Complete | CandidatePhase::Aborted
                ) =>
            {
                CandidatePhase::Aborted
            }
            (CandidatePhase::Prepared, CandidateEvent::Spawned) => CandidatePhase::Spawned,
            (CandidatePhase::Spawned, CandidateEvent::GuestResultCaptured) => {
                CandidatePhase::GuestResultCaptured
            }
            (CandidatePhase::GuestResultCaptured, CandidateEvent::DirectProcessReaped) => {
                CandidatePhase::DirectProcessReaped
            }
            (CandidatePhase::DirectProcessReaped, CandidateEvent::DescendantsEmpty) => {
                CandidatePhase::DescendantsEmpty
            }
            (CandidatePhase::DescendantsEmpty, CandidateEvent::ResidueRemoved) => {
                CandidatePhase::ResidueRemoved
            }
            (CandidatePhase::ResidueRemoved, CandidateEvent::Complete) => CandidatePhase::Complete,
            _ => {
                return Err(CandidateLifecycleError {
                    phase: self.phase,
                    event,
                });
            }
        };
        self.phase = next;
        Ok(())
    }
}

#[cfg(feature = "candidate-probe")]
pub mod candidate_probe {
    use super::*;
    use keep_native_linux_abi::{PinnedDirectory, seal_data_file_bytes};
    use std::fs::{OpenOptions, create_dir, create_dir_all, set_permissions};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct CandidateFixtureRoot(std::path::PathBuf);

    impl Drop for CandidateFixtureRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub struct ConstructedCandidateFixture {
        pub root: std::path::PathBuf,
        pub secrets: CandidateFixtureSecrets,
        launch_measurements: Vec<(String, [u8; 32])>,
    }

    pub struct CandidateRunObservation {
        pub guest: CandidateGuestResult,
        pub jailer_exit_success: bool,
        pub containment: CandidateLiveContainmentObservation,
        pub landlock: CandidateLandlockObservation,
        pub seccomp: CandidateSeccompObservation,
        pub cgroup: CandidateCgroupObservation,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CandidateSeccompObservation {
        pub policy_source_sha256: String,
        pub compiler_sha256: String,
        pub compiled_policy_sha256: String,
        pub target_architecture: String,
        pub live_thread_count: u32,
        pub filters_per_thread: u32,
    }

    impl CandidateSeccompObservation {
        pub fn verify(&self) -> Result<(), CandidateRefusal> {
            if self.policy_source_sha256
                != "1b683d5c9fc51174ab1926b84aaf10dc2164678f6c2fe7c38a910556d7b5dc39"
                || self.compiler_sha256
                    != "0a6d20e734f0e6c1d9cf8372fdc478675f301219c141064e4cea9c0582e37cc8"
                || self.compiled_policy_sha256
                    != "6a6dfed43d1417a244a999f5bd63679173bf03254dd50f19a9ac4db160c6b0fc"
                || self.target_architecture != "x86_64"
                || self.live_thread_count < 2
                || self.filters_per_thread != 1
            {
                return Err(CandidateRefusal::DirectProcessFailed);
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CandidateLandlockObservation {
        pub abi: u32,
        pub handled_filesystem: u64,
        pub handled_network: u64,
        pub scoped: u64,
        pub denied_write_errno: u8,
        pub denied_create_errno: u8,
    }

    impl CandidateLandlockObservation {
        pub fn verify(&self) -> Result<(), CandidateRefusal> {
            let expected = reviewed_landlock_policy(self.abi)
                .map_err(|_| CandidateRefusal::DirectProcessFailed)?;
            if self.abi < 4
                || self.handled_filesystem != expected.handled_filesystem
                || self.handled_network != expected.handled_network
                || self.scoped != expected.scoped
                || self.denied_write_errno != 13
                || self.denied_create_errno != 13
            {
                return Err(CandidateRefusal::DirectProcessFailed);
            }
            Ok(())
        }
    }

    fn parse_canonical_hex_u64(value: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let parsed = u64::from_str_radix(value, 16)?;
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            || format!("{parsed:x}") != value
        {
            return Err("Landlock marker mask is not canonical lowercase hexadecimal".into());
        }
        Ok(parsed)
    }

    pub(crate) fn parse_landlock_observation(
        stderr: &[u8],
    ) -> Result<CandidateLandlockObservation, Box<dyn std::error::Error>> {
        const PREFIX: &str = "[keep-prober-landlock] ";
        let text = std::str::from_utf8(stderr)?;
        let mut markers = text.lines().filter_map(|line| line.strip_prefix(PREFIX));
        let marker = markers.next().ok_or("Landlock activation marker absent")?;
        if markers.next().is_some() {
            return Err("Landlock activation marker duplicated".into());
        }
        let fields = marker.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 6 {
            return Err("Landlock activation marker fields differ".into());
        }
        let field = |index: usize, prefix: &str| {
            fields[index]
                .strip_prefix(prefix)
                .ok_or("Landlock activation marker key differs")
        };
        let observation = CandidateLandlockObservation {
            abi: field(0, "abi=")?.parse()?,
            handled_filesystem: parse_canonical_hex_u64(field(1, "fs=")?)?,
            handled_network: parse_canonical_hex_u64(field(2, "net=")?)?,
            scoped: parse_canonical_hex_u64(field(3, "scoped=")?)?,
            denied_write_errno: field(4, "deniedWrite=")?.parse()?,
            denied_create_errno: field(5, "deniedCreate=")?.parse()?,
        };
        observation.verify()?;
        Ok(observation)
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CandidateLiveContainmentObservation {
        pub host_pid: u32,
        pub uid: u32,
        pub seccomp_mode: u8,
        pub seccomp_thread_count: u32,
        pub seccomp_filters_per_thread: u32,
        pub pid_namespace_isolated: bool,
        pub mount_namespace_isolated: bool,
        pub chroot_matches_jail: bool,
        pub capabilities_empty: bool,
        pub socket_descriptors_absent: bool,
        pub environment_empty: bool,
        pub inherited_descriptor_absent: bool,
    }

    impl CandidateLiveContainmentObservation {
        pub fn verify(&self) -> Result<(), CandidateRefusal> {
            if self.host_pid == 0
                || !(300_000..340_000).contains(&self.uid)
                || self.seccomp_mode != 2
                || self.seccomp_thread_count < 2
                || self.seccomp_filters_per_thread != 1
                || !self.pid_namespace_isolated
                || !self.mount_namespace_isolated
                || !self.chroot_matches_jail
                || !self.capabilities_empty
                || !self.socket_descriptors_absent
                || !self.environment_empty
                || !self.inherited_descriptor_absent
            {
                return Err(CandidateRefusal::DirectProcessFailed);
            }
            Ok(())
        }
    }

    fn status_field<'a>(
        status: &'a str,
        name: &str,
    ) -> Result<&'a str, Box<dyn std::error::Error>> {
        let prefix = format!("{name}:");
        let mut matches = status
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix).map(str::trim));
        let value = matches.next().ok_or("process status field absent")?;
        if matches.next().is_some() {
            return Err("process status field duplicated".into());
        }
        Ok(value)
    }

    fn observe_live_containment(
        pid: u32,
        uid: u32,
        jail_guest_root: &Path,
        inherited_canary_identity: (u64, u64),
    ) -> Result<CandidateLiveContainmentObservation, Box<dyn std::error::Error>> {
        let process_root = format!("/proc/{pid}");
        let status = std::fs::read_to_string(format!("{process_root}/status"))?;
        let exact_ids = format!("{uid}\t{uid}\t{uid}\t{uid}");
        if status_field(&status, "Uid")? != exact_ids || status_field(&status, "Gid")? != exact_ids
        {
            return Err("native PROBER descendant real/effective/saved/fs IDs differ".into());
        }
        let capabilities_empty = ["CapInh", "CapPrm", "CapEff", "CapAmb"]
            .into_iter()
            .all(|name| status_field(&status, name).is_ok_and(|value| value == "0000000000000000"));
        let process_seccomp_mode = status_field(&status, "Seccomp")?.parse::<u8>()?;
        let task_root = format!("{process_root}/task");
        let task_ids = || -> io::Result<Vec<String>> {
            let mut ids = std::fs::read_dir(&task_root)?
                .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
                .collect::<Result<Vec<_>, _>>()?;
            ids.sort();
            Ok(ids)
        };
        let before_tasks = task_ids()?;
        let mut seccomp_filters_per_thread = None;
        let mut all_threads_filtered = process_seccomp_mode == 2;
        for task in &before_tasks {
            let task_status = std::fs::read_to_string(format!("{task_root}/{task}/status"))?;
            if status_field(&task_status, "Seccomp")? != "2" {
                all_threads_filtered = false;
                continue;
            }
            let filters = status_field(&task_status, "Seccomp_filters")?.parse::<u32>()?;
            if filters == 0
                || seccomp_filters_per_thread
                    .replace(filters)
                    .is_some_and(|prior| prior != filters)
            {
                return Err("native PROBER Firecracker thread seccomp filter counts differ".into());
            }
        }
        if task_ids()? != before_tasks {
            return Err(
                "native PROBER Firecracker thread inventory changed during appraisal".into(),
            );
        }
        let seccomp_mode = if all_threads_filtered { 2 } else { 0 };
        let seccomp_filters_per_thread = if all_threads_filtered {
            seccomp_filters_per_thread.ok_or("seccomp thread evidence absent")?
        } else {
            0
        };
        let nspid = status_field(&status, "NSpid")?
            .split_ascii_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()?;
        let pid_namespace_isolated = nspid.len() == 2 && nspid[0] == pid && nspid[1] == 1;
        let namespace_differs = |name: &str| -> io::Result<bool> {
            let host = std::fs::metadata(format!("/proc/self/ns/{name}"))?;
            let child = std::fs::metadata(format!("{process_root}/ns/{name}"))?;
            Ok(host.dev() != child.dev() || host.ino() != child.ino())
        };
        let mount_namespace_isolated = namespace_differs("mnt")?;
        let pid_namespace_inode_isolated = namespace_differs("pid")?;
        let jail = std::fs::metadata(jail_guest_root)?;
        let child_root = std::fs::metadata(format!("{process_root}/root"))?;
        let chroot_matches_jail = jail.dev() == child_root.dev() && jail.ino() == child_root.ino();
        let descriptor_entries =
            std::fs::read_dir(format!("{process_root}/fd"))?.collect::<Result<Vec<_>, _>>()?;
        let socket_descriptors_absent = descriptor_entries.iter().all(|entry| {
            std::fs::read_link(entry.path())
                .is_ok_and(|target| !target.to_string_lossy().starts_with("socket:["))
        });
        let inherited_descriptor_absent = descriptor_entries.iter().all(|entry| {
            entry
                .metadata()
                .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) != inherited_canary_identity)
        });
        let environment_empty = std::fs::read(format!("{process_root}/environ"))?.is_empty();
        if !capabilities_empty
            || !pid_namespace_isolated
            || !pid_namespace_inode_isolated
            || !mount_namespace_isolated
            || !chroot_matches_jail
            || !socket_descriptors_absent
            || !environment_empty
            || !inherited_descriptor_absent
        {
            return Err(format!(
                "native PROBER live containment mismatch: caps={capabilities_empty} nspid={pid_namespace_isolated} pidns={pid_namespace_inode_isolated} mntns={mount_namespace_isolated} chroot={chroot_matches_jail} socketsAbsent={socket_descriptors_absent} envEmpty={environment_empty} inheritedFdAbsent={inherited_descriptor_absent}"
            )
            .into());
        }
        Ok(CandidateLiveContainmentObservation {
            host_pid: pid,
            uid,
            seccomp_mode,
            seccomp_thread_count: before_tasks.len().try_into()?,
            seccomp_filters_per_thread,
            pid_namespace_isolated,
            mount_namespace_isolated,
            chroot_matches_jail,
            capabilities_empty,
            socket_descriptors_absent,
            environment_empty,
            inherited_descriptor_absent,
        })
    }

    fn measure_pinned_file(
        file: &keep_native_linux_abi::PinnedRegularFile,
        maximum_bytes: u64,
    ) -> io::Result<[u8; 32]> {
        let mut measurement = Sha256State::new();
        let total = file.read_bounded_chunks(maximum_bytes, |chunk| {
            measurement.update(chunk);
            Ok(())
        })?;
        if total != file.identity().size {
            return Err(io::Error::other("launch measurement length changed"));
        }
        Ok(measurement.finalize())
    }

    struct CandidateUidLease {
        uid: u32,
        path: std::path::PathBuf,
    }

    impl Drop for CandidateUidLease {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn uid_has_live_process(uid: u32) -> bool {
        let Ok(processes) = std::fs::read_dir("/proc") else {
            return true;
        };
        for process in processes.flatten() {
            if !process
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            {
                continue;
            }
            if process
                .metadata()
                .is_ok_and(|metadata| metadata.uid() == uid)
            {
                return true;
            }
        }
        false
    }

    fn id_is_named(path: &str, id: u32) -> Result<bool, Box<dyn std::error::Error>> {
        for line in std::fs::read_to_string(path)?.lines() {
            let fields: Vec<_> = line.split(':').collect();
            if fields.len() < 3 {
                return Err(format!("malformed identity registry: {path}").into());
            }
            if fields[2].parse::<u32>()? == id {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn id_is_delegated(path: &str, id: u32) -> Result<bool, Box<dyn std::error::Error>> {
        for line in std::fs::read_to_string(path)?.lines() {
            let fields: Vec<_> = line.split(':').collect();
            if fields.len() != 3 {
                return Err(format!("malformed subordinate identity registry: {path}").into());
            }
            let start = fields[1].parse::<u32>()?;
            let count = fields[2].parse::<u32>()?;
            let end = start
                .checked_add(count)
                .ok_or("subordinate identity range overflow")?;
            if id >= start && id < end {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn uid_is_reserved(uid: u32) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(id_is_named("/etc/passwd", uid)?
            || id_is_named("/etc/group", uid)?
            || id_is_delegated("/etc/subuid", uid)?
            || id_is_delegated("/etc/subgid", uid)?)
    }

    fn acquire_uid_lease(
        work_root: &Path,
        attempt: &CandidateAttemptId,
    ) -> Result<CandidateUidLease, Box<dyn std::error::Error>> {
        let root = work_root.join(".uid-leases");
        create_dir_all(&root)?;
        set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let metadata = std::fs::symlink_metadata(&root)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o777 != 0o700
        {
            return Err("candidate UID lease root is not private root-owned storage".into());
        }
        let nonce = attempt
            .as_str()
            .strip_prefix("keep-")
            .ok_or("attempt prefix")?;
        let start = u32::from_str_radix(&nonce[..8], 16)? % 40_000;
        for offset in 0..40_000u32 {
            let uid = 300_000 + (start + offset) % 40_000;
            if uid_is_reserved(uid)? || uid_has_live_process(uid) {
                continue;
            }
            let path = root.join(uid.to_string());
            match OpenOptions::new().create_new(true).write(true).open(&path) {
                Ok(mut file) => {
                    use std::io::Write as _;
                    file.write_all(format!("{}\n", attempt.as_str()).as_bytes())?;
                    file.sync_all()?;
                    if uid_has_live_process(uid) {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    return Ok(CandidateUidLease { uid, path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err("candidate UID lease space is exhausted".into())
    }

    impl Drop for ConstructedCandidateFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn run_image_tool(
        executable: &Path,
        arguments: &[String],
        environment: &[(&str, &str)],
        root: &Path,
        sequence: usize,
        deadline: &CandidateDeadline,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let output = |stream| {
            OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(root.join(format!("tool-{sequence}-{stream}")))
        };
        let stdout = output("stdout")?;
        let stderr = output("stderr")?;
        let result = CandidateDirectProcess::spawn(
            executable,
            arguments,
            environment,
            root,
            stdout,
            stderr,
        )?
        .wait_bounded(deadline, 2 * 1024 * 1024)?;
        let stdout_path = root.join(format!("tool-{sequence}-stdout"));
        let stderr_path = root.join(format!("tool-{sequence}-stderr"));
        let stdout_bytes = std::fs::read(&stdout_path).unwrap_or_default();
        let stderr_tail = std::fs::read(&stderr_path).unwrap_or_default();
        let _ = std::fs::remove_file(&stdout_path);
        let _ = std::fs::remove_file(&stderr_path);
        if !result.status.success() {
            return Err(format!(
                "fixed image tool failed: {}",
                String::from_utf8_lossy(&stderr_tail)
            )
            .into());
        }
        Ok(stdout_bytes)
    }

    fn construct_authenticated_fixture_with_request(
        _enrollment: &CandidateProbeEnrollment,
        request_script: &[u8],
    ) -> Result<ConstructedCandidateFixture, Box<dyn std::error::Error>> {
        const WORK_ROOT: &str = "/var/lib/keep/native-prober-candidate";
        create_dir_all(WORK_ROOT)?;
        set_permissions(WORK_ROOT, std::fs::Permissions::from_mode(0o700))?;
        let metadata = std::fs::symlink_metadata(WORK_ROOT)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(
                "native PROBER candidate work root is not private root-owned storage".into(),
            );
        }
        let secrets = mint_candidate_fixture_secrets()?;
        let work = PinnedDirectory::open(Path::new(WORK_ROOT))?;
        let attempt = work.create_private_directory(secrets.attempt_id.as_str())?;
        let root = Path::new(WORK_ROOT).join(secrets.attempt_id.as_str());
        let cleanup = CandidateFixtureRoot(root.clone());

        let runtime = PinnedDirectory::open(Path::new(
            "/root/keep-infra/firecracker/release-v1.16.1-x86_64",
        ))?;
        let images = PinnedDirectory::open(Path::new("/root/keep-infra/firecracker"))?;
        let tools = PinnedDirectory::open(Path::new("/usr/sbin"))?;
        let configuration = PinnedDirectory::open(Path::new("/etc"))?;
        let repository_assets =
            PinnedDirectory::open(Path::new("/root/keep-canonical/keep/assets/microvm"))?;
        let native_candidate_build = PinnedDirectory::open(Path::new(
            "/root/keep-canonical/keep/native/target/x86_64-unknown-linux-musl/debug",
        ))?;
        for (destination, source_root, source, maximum, mode, expected_sha256) in [
            (
                "jailer",
                &runtime,
                "jailer-v1.16.1-x86_64",
                4 * 1024 * 1024,
                0o500,
                "1f3a0c1fe86212d0001819bfe0819071c01208b3ccc9398c3b3bc1b84cf21edd",
            ),
            (
                "firecracker-vmm",
                &runtime,
                "firecracker-v1.16.1-x86_64",
                8 * 1024 * 1024,
                0o500,
                "2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7",
            ),
            (
                "seccomp-source.json",
                &runtime,
                "seccomp-filter-v1.16.1-x86_64.json",
                64 * 1024,
                0o400,
                "1b683d5c9fc51174ab1926b84aaf10dc2164678f6c2fe7c38a910556d7b5dc39",
            ),
            (
                "seccompiler",
                &runtime,
                "seccompiler-bin-v1.16.1-x86_64",
                2 * 1024 * 1024,
                0o500,
                "0a6d20e734f0e6c1d9cf8372fdc478675f301219c141064e4cea9c0582e37cc8",
            ),
            (
                "firecracker-SHA256SUMS",
                &runtime,
                "SHA256SUMS",
                4096,
                0o400,
                "3a1f96bf847c561604f62f632f63ed40f28325dafbef8b2eb0cb6625aa51ff86",
            ),
            (
                "firecracker",
                &native_candidate_build,
                "keep-native-prober-vmm-shim.installed",
                8 * 1024 * 1024,
                0o500,
                "ab8f351884cb8ddaefaf6177ccd7ce703bf53a1f989fbce659a1bdebdcc5148c",
            ),
            (
                "vmlinux",
                &images,
                "vmlinux",
                64 * 1024 * 1024,
                0o400,
                "e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2",
            ),
            (
                "rootfs.ext4",
                &images,
                "rootfs-keep.ext4",
                600 * 1024 * 1024,
                0o600,
                "01e8f08e33987f653aa4b6b3edc2dd1c6d1ef311d1539c6d33abc3acc56cf5a3",
            ),
            (
                "keep-init",
                &repository_assets,
                "keep-init",
                1024 * 1024,
                0o500,
                "4a68a4bb07b2699af22b2137d65ba0040c9639d5c2bce01dc9905d7c0240da32",
            ),
            (
                "debugfs",
                &tools,
                "debugfs",
                2 * 1024 * 1024,
                0o500,
                "1e83118cc9582afcad2711fbb7f40f56668adccb386d988cb6d9ad5c2d001049",
            ),
            (
                "mke2fs",
                &tools,
                "mke2fs",
                2 * 1024 * 1024,
                0o500,
                "07cd24ce58a410cc9cee93c55ae5ac95986df016c5907dc7a49b55389bd41ed2",
            ),
            (
                "e2fsck",
                &tools,
                "e2fsck",
                2 * 1024 * 1024,
                0o500,
                "c69c6315f602d389821b3a1dab1308618616259400f2cf5d997243c4a83c284c",
            ),
            (
                "mke2fs.conf",
                &configuration,
                "mke2fs.conf",
                64 * 1024,
                0o400,
                "def9e1d4dbf51f44c51303349338086cf23d60c3cc7e9e99442ee554eb9f5de6",
            ),
        ] {
            let source = source_root.open_regular_file(source, maximum)?;
            if bytes_hex(&measure_pinned_file(&source, maximum)?) != expected_sha256 {
                return Err(format!(
                    "installed candidate input measurement differs: {destination}"
                )
                .into());
            }
            attempt.stage_private_copy(destination, &source, maximum, mode)?;
        }
        let nonce_bytes = format!("{}\n", secrets.result_nonce).into_bytes();
        let ipad_bytes = format!("{}\n", bytes_hex(&secrets.authentication_ipad)).into_bytes();
        let opad_bytes = format!("{}\n", bytes_hex(&secrets.authentication_opad)).into_bytes();
        attempt.stage_private_file("nonce", &nonce_bytes, 128, 0o400)?;
        attempt.stage_private_file("ipad", &ipad_bytes, 256, 0o400)?;
        attempt.stage_private_file("opad", &opad_bytes, 256, 0o400)?;
        attempt.stage_private_file("config.json", &fixed_firecracker_config(), 16 * 1024, 0o400)?;

        let project_source = root.join("project-source");
        let keep_source = project_source.join(".keep");
        create_dir(&project_source)?;
        create_dir(&keep_source)?;
        set_permissions(&project_source, std::fs::Permissions::from_mode(0o755))?;
        set_permissions(&keep_source, std::fs::Permissions::from_mode(0o700))?;
        let request_path = keep_source.join("request.sh");
        let mut request = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&request_path)?;
        use std::io::Write as _;
        request.write_all(request_script)?;
        request.sync_all()?;
        set_permissions(&request_path, std::fs::Permissions::from_mode(0o700))?;
        attempt.stage_private_file("project.ext4", b"", 1, 0o600)?;

        let deadline = CandidateDeadline::start(MAXIMUM_LAUNCH_MILLISECONDS)?;
        let release_manifest = std::fs::read_to_string(root.join("firecracker-SHA256SUMS"))?;
        for expected in [
            "1b683d5c9fc51174ab1926b84aaf10dc2164678f6c2fe7c38a910556d7b5dc39  ./seccomp-filter-v1.16.1-x86_64.json",
            "0a6d20e734f0e6c1d9cf8372fdc478675f301219c141064e4cea9c0582e37cc8  ./seccompiler-bin-v1.16.1-x86_64",
        ] {
            if release_manifest
                .lines()
                .filter(|line| *line == expected)
                .count()
                != 1
            {
                return Err("Firecracker release manifest seccomp equation differs".into());
            }
        }
        for (sequence, output) in [(0usize, "seccomp-a.bpf"), (1usize, "seccomp-b.bpf")] {
            run_image_tool(
                &root.join("seccompiler"),
                &[
                    "--target-arch".into(),
                    "x86_64".into(),
                    "--input-file".into(),
                    root.join("seccomp-source.json").display().to_string(),
                    "--output-file".into(),
                    root.join(output).display().to_string(),
                ],
                &[],
                &root,
                sequence,
                &deadline,
            )?;
        }
        let seccomp_bytes = std::fs::read(root.join("seccomp-a.bpf"))?;
        let mut seccomp_measurement = Sha256State::new();
        seccomp_measurement.update(&seccomp_bytes);
        if seccomp_bytes.len() != 3162
            || bytes_hex(&seccomp_measurement.finalize())
                != "6a6dfed43d1417a244a999f5bd63679173bf03254dd50f19a9ac4db160c6b0fc"
            || seccomp_bytes != std::fs::read(root.join("seccomp-b.bpf"))?
        {
            return Err("Firecracker seccomp compilation is not exact deterministic output".into());
        }
        std::fs::rename(root.join("seccomp-a.bpf"), root.join("seccomp.bpf"))?;
        std::fs::remove_file(root.join("seccomp-b.bpf"))?;
        set_permissions(
            root.join("seccomp.bpf"),
            std::fs::Permissions::from_mode(0o400),
        )?;
        attempt.stage_private_file(
            "seccomp-canary.json",
            SECCOMP_DENIAL_CANARY_SOURCE,
            4096,
            0o400,
        )?;
        for (sequence, output) in [
            (2usize, "seccomp-canary-a.bpf"),
            (3usize, "seccomp-canary-b.bpf"),
        ] {
            run_image_tool(
                &root.join("seccompiler"),
                &[
                    "--target-arch".into(),
                    "x86_64".into(),
                    "--input-file".into(),
                    root.join("seccomp-canary.json").display().to_string(),
                    "--output-file".into(),
                    root.join(output).display().to_string(),
                ],
                &[],
                &root,
                sequence,
                &deadline,
            )?;
        }
        if std::fs::read(root.join("seccomp-canary-a.bpf"))?
            != std::fs::read(root.join("seccomp-canary-b.bpf"))?
        {
            return Err("Firecracker seccomp denial-canary compilation is nondeterministic".into());
        }
        std::fs::rename(
            root.join("seccomp-canary-a.bpf"),
            root.join("seccomp-canary.bpf"),
        )?;
        std::fs::remove_file(root.join("seccomp-canary-b.bpf"))?;
        set_permissions(
            root.join("seccomp-canary.bpf"),
            std::fs::Permissions::from_mode(0o400),
        )?;
        let debugfs = root.join("debugfs");
        let staged_rootfs = root.join("rootfs.ext4");
        let mut sequence = 4usize;
        for command in [
            "rm /keep-init".to_owned(),
            "rm /keep-secrets/nonce".to_owned(),
            "rm /keep-secrets/ipad".to_owned(),
            "rm /keep-secrets/opad".to_owned(),
            "rmdir /keep-secrets".to_owned(),
            format!("write {} /keep-init", root.join("keep-init").display()),
            "mkdir /keep-secrets".to_owned(),
            format!("write {} /keep-secrets/nonce", root.join("nonce").display()),
            format!("write {} /keep-secrets/ipad", root.join("ipad").display()),
            format!("write {} /keep-secrets/opad", root.join("opad").display()),
            "set_inode_field /keep-init mode 0100755".to_owned(),
            "set_inode_field /keep-secrets mode 040700".to_owned(),
            "set_inode_field /keep-secrets/nonce mode 0100600".to_owned(),
            "set_inode_field /keep-secrets/ipad mode 0100600".to_owned(),
            "set_inode_field /keep-secrets/opad mode 0100600".to_owned(),
        ] {
            run_image_tool(
                &debugfs,
                &[
                    "-w".into(),
                    "-R".into(),
                    command,
                    staged_rootfs.display().to_string(),
                ],
                &[],
                &root,
                sequence,
                &deadline,
            )?;
            sequence += 1;
        }
        let e2fsck = root.join("e2fsck");
        run_image_tool(
            &e2fsck,
            &["-fy".into(), staged_rootfs.display().to_string()],
            &[],
            &root,
            sequence,
            &deadline,
        )?;
        sequence += 1;
        let mke2fs_config = root.join("mke2fs.conf").display().to_string();
        run_image_tool(
            &root.join("mke2fs"),
            &[
                "-q".into(),
                "-F".into(),
                "-t".into(),
                "ext4".into(),
                "-d".into(),
                project_source.display().to_string(),
                root.join("project.ext4").display().to_string(),
                "65536K".into(),
            ],
            &[("MKE2FS_CONFIG", mke2fs_config.as_str()), ("LC_ALL", "C")],
            &root,
            sequence,
            &deadline,
        )?;
        sequence += 1;
        run_image_tool(
            &e2fsck,
            &[
                "-fn".into(),
                root.join("project.ext4").display().to_string(),
            ],
            &[],
            &root,
            sequence,
            &deadline,
        )?;
        sequence += 1;
        for (image, guest, output, expected) in [
            (
                &staged_rootfs,
                "/keep-init",
                "readback-keep-init",
                CANDIDATE_REQUEST_SCRIPT,
            ),
            (
                &root.join("project.ext4"),
                "/.keep/request.sh",
                "readback-request",
                request_script,
            ),
        ] {
            run_image_tool(
                &debugfs,
                &[
                    "-R".into(),
                    format!("dump {guest} {}", root.join(output).display()),
                    image.display().to_string(),
                ],
                &[],
                &root,
                sequence,
                &deadline,
            )?;
            sequence += 1;
            let actual = std::fs::read(root.join(output))?;
            if guest == "/keep-init" {
                if actual != std::fs::read(root.join("keep-init"))? {
                    return Err("constructed rootfs guest init readback differs".into());
                }
            } else if actual != expected {
                return Err("constructed project request readback differs".into());
            }
        }
        for (guest, output, expected) in [
            (
                "/keep-secrets/nonce",
                "readback-nonce",
                nonce_bytes.as_slice(),
            ),
            ("/keep-secrets/ipad", "readback-ipad", ipad_bytes.as_slice()),
            ("/keep-secrets/opad", "readback-opad", opad_bytes.as_slice()),
        ] {
            run_image_tool(
                &debugfs,
                &[
                    "-R".into(),
                    format!("dump {guest} {}", root.join(output).display()),
                    staged_rootfs.display().to_string(),
                ],
                &[],
                &root,
                sequence,
                &deadline,
            )?;
            sequence += 1;
            if std::fs::read(root.join(output))? != expected {
                return Err("constructed rootfs authentication material readback differs".into());
            }
        }
        for (image, guest, object_type, mode) in [
            (&staged_rootfs, "/keep-init", "regular", "0755"),
            (&staged_rootfs, "/keep-secrets", "directory", "0700"),
            (&staged_rootfs, "/keep-secrets/nonce", "regular", "0600"),
            (&staged_rootfs, "/keep-secrets/ipad", "regular", "0600"),
            (&staged_rootfs, "/keep-secrets/opad", "regular", "0600"),
            (&root.join("project.ext4"), "/.keep", "directory", "0700"),
            (
                &root.join("project.ext4"),
                "/.keep/request.sh",
                "regular",
                "0700",
            ),
        ] {
            let status = run_image_tool(
                &debugfs,
                &[
                    "-R".into(),
                    format!("stat {guest}"),
                    image.display().to_string(),
                ],
                &[],
                &root,
                sequence,
                &deadline,
            )?;
            sequence += 1;
            let status = String::from_utf8(status)?;
            if !status.contains(&format!("Type: {object_type}"))
                || !status.contains(&format!("Mode:  {mode}"))
                || !status.contains("User:     0   Group:     0")
                || (object_type == "regular" && !status.contains("Links: 1"))
            {
                return Err(format!("constructed guest object identity differs: {guest}").into());
            }
        }
        std::fs::remove_dir_all(&project_source)?;
        let completed = PinnedDirectory::open(&root)?;
        let mut launch_measurements = Vec::with_capacity(9);
        for (name, maximum) in [
            ("jailer", 4 * 1024 * 1024),
            ("firecracker", 8 * 1024 * 1024),
            ("firecracker-vmm", 8 * 1024 * 1024),
            ("vmlinux", 64 * 1024 * 1024),
            ("rootfs.ext4", 600 * 1024 * 1024),
            ("project.ext4", 128 * 1024 * 1024),
            ("config.json", 16 * 1024),
            ("seccomp.bpf", 4096),
            ("seccomp-canary.bpf", 4096),
        ] {
            let captured = completed.open_regular_file(name, maximum)?;
            launch_measurements.push((name.to_owned(), measure_pinned_file(&captured, maximum)?));
        }
        std::mem::forget(cleanup);
        Ok(ConstructedCandidateFixture {
            root,
            secrets,
            launch_measurements,
        })
    }

    pub fn construct_authenticated_fixture(
        enrollment: &CandidateProbeEnrollment,
    ) -> Result<ConstructedCandidateFixture, Box<dyn std::error::Error>> {
        construct_authenticated_fixture_with_request(enrollment, CANDIDATE_REQUEST_SCRIPT)
    }

    fn launch_authenticated_fixture_bounded(
        _enrollment: &CandidateProbeEnrollment,
        fixture: &ConstructedCandidateFixture,
        maximum_launch_milliseconds: u64,
        extra_vmm_argument: Option<&str>,
        use_seccomp_canary: bool,
    ) -> Result<CandidateRunObservation, Box<dyn std::error::Error>> {
        const JAIL_ROOT: &str = "/var/lib/keep/native-prober-jails";
        create_dir_all(JAIL_ROOT)?;
        set_permissions(JAIL_ROOT, std::fs::Permissions::from_mode(0o700))?;
        let jail_metadata = std::fs::symlink_metadata(JAIL_ROOT)?;
        if !jail_metadata.is_dir()
            || jail_metadata.file_type().is_symlink()
            || jail_metadata.uid() != 0
            || jail_metadata.gid() != 0
            || jail_metadata.mode() & 0o777 != 0o700
        {
            return Err("native PROBER jail root is not private root-owned storage".into());
        }
        let lease = acquire_uid_lease(Path::new(JAIL_ROOT), &fixture.secrets.attempt_id)?;
        let jail_parent = Path::new(JAIL_ROOT)
            .join("firecracker")
            .join(fixture.secrets.attempt_id.as_str());
        let jail_guest_root = jail_parent.join("root");
        create_dir_all(&jail_guest_root)?;
        set_permissions(&jail_guest_root, std::fs::Permissions::from_mode(0o700))?;
        struct JailCleanup(std::path::PathBuf);
        impl Drop for JailCleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let jail_cleanup = JailCleanup(jail_parent.clone());
        let source = PinnedDirectory::open(&fixture.root)?;
        let destination = PinnedDirectory::open(&jail_guest_root)?;
        let jailer = source.open_regular_file("jailer", 4 * 1024 * 1024)?;
        let expected_jailer = fixture
            .launch_measurements
            .iter()
            .find(|(name, _)| name == "jailer")
            .ok_or("jailer launch measurement missing")?;
        if measure_pinned_file(&jailer, 4 * 1024 * 1024)? != expected_jailer.1 {
            return Err("jailer changed after authenticated construction".into());
        }
        for (source_name, destination_name, maximum, mode) in [
            ("firecracker-vmm", "firecracker-vmm", 8 * 1024 * 1024, 0o500),
            ("vmlinux", "vmlinux", 64 * 1024 * 1024, 0o400),
            ("rootfs.ext4", "rootfs.ext4", 600 * 1024 * 1024, 0o400),
            ("project.ext4", "project.ext4", 128 * 1024 * 1024, 0o600),
            ("config.json", "config.json", 16 * 1024, 0o400),
            (
                if use_seccomp_canary {
                    "seccomp-canary.bpf"
                } else {
                    "seccomp.bpf"
                },
                "seccomp.bpf",
                4096,
                0o400,
            ),
        ] {
            let input = source.open_regular_file(source_name, maximum)?;
            let expected = fixture
                .launch_measurements
                .iter()
                .find(|(measured_name, _)| measured_name == source_name)
                .ok_or("launch measurement missing")?;
            if measure_pinned_file(&input, maximum)? != expected.1 {
                return Err("launch input changed after authenticated construction".into());
            }
            destination.stage_private_copy(destination_name, &input, maximum, mode)?;
            std::os::unix::fs::chown(
                jail_guest_root.join(destination_name),
                Some(lease.uid),
                Some(lease.uid),
            )?;
        }
        destination.stage_private_file(
            "landlock-denied-canary",
            LANDLOCK_DENIED_CANARY_BYTES,
            128,
            0o600,
        )?;
        std::os::unix::fs::chown(
            jail_guest_root.join("landlock-denied-canary"),
            Some(lease.uid),
            Some(lease.uid),
        )?;
        let shim = source.open_regular_file("firecracker", 8 * 1024 * 1024)?;
        let expected_shim = fixture
            .launch_measurements
            .iter()
            .find(|(name, _)| name == "firecracker")
            .ok_or("post-jailer shim launch measurement missing")?;
        if measure_pinned_file(&shim, 8 * 1024 * 1024)? != expected_shim.1 {
            return Err("post-jailer shim changed after authenticated construction".into());
        }
        let stdout_path = fixture.root.join("jailer-stdout");
        let stderr_path = fixture.root.join("jailer-stderr");
        let stdout = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&stdout_path)?;
        let stderr = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&stderr_path)?;
        let mut arguments = fixed_jailer_arguments(&fixture.secrets.attempt_id, lease.uid);
        arguments.splice(
            2..2,
            [
                "--exec-file".to_owned(),
                fixture.root.join("firecracker").display().to_string(),
                "--chroot-base-dir".to_owned(),
                JAIL_ROOT.to_owned(),
            ],
        );
        if let Some(argument) = extra_vmm_argument {
            arguments.push(argument.to_owned());
        }
        if use_seccomp_canary {
            arguments.push("--keep-seccomp-canary".into());
        }
        let mut lifecycle = CandidateLifecycle::prepared();
        struct CgroupCleanup {
            path: std::path::PathBuf,
            uid: u32,
            active: bool,
        }
        impl Drop for CgroupCleanup {
            fn drop(&mut self) {
                if !self.active {
                    return;
                }
                if self.path.exists() {
                    let _ = std::fs::write(self.path.join("cgroup.kill"), b"1\n");
                    for _ in 0..100 {
                        let empty = std::fs::read_to_string(self.path.join("cgroup.events"))
                            .is_ok_and(|events| events.lines().any(|line| line == "populated 0"));
                        if empty {
                            break;
                        }
                        sleep(Duration::from_millis(5));
                    }
                    let _ = std::fs::remove_dir(&self.path);
                }
                // If jailer's naming contract ever changes, the leased UID remains an
                // independent fail-safe process selector rather than leaving an orphan.
                for process in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
                    if process
                        .metadata()
                        .is_ok_and(|metadata| metadata.uid() == self.uid)
                    {
                        if let Ok(pid) = process.file_name().to_string_lossy().parse::<u32>() {
                            if let Ok(identity) = ProcessIdentity::open(pid) {
                                let _ = identity.kill();
                            }
                        }
                    }
                }
            }
        }
        // With this fixed `keep-<nonce>` jail ID, jailer v1.16.1 creates the v2 leaf
        // directly beneath the parent using that exact ID.
        let cgroup_leaf_name = fixture.secrets.attempt_id.as_str().to_owned();
        let cgroup_path = Path::new("/sys/fs/cgroup/keep").join(&cgroup_leaf_name);
        let mut cgroup_cleanup = CgroupCleanup {
            path: cgroup_path.clone(),
            uid: lease.uid,
            active: true,
        };
        let deadline = CandidateDeadline::start(maximum_launch_milliseconds)?;
        let inherited_canary = seal_data_file_bytes(
            "keep-authority-canary",
            b"must-not-reach-native-prober-vmm",
            64,
            0o400,
        )?;
        let inherited_canary_descriptor = inherited_canary.make_inheritable()?;
        let inherited_canary_metadata =
            std::fs::metadata(format!("/proc/self/fd/{inherited_canary_descriptor}"))?;
        let inherited_canary_identity = (
            inherited_canary_metadata.dev(),
            inherited_canary_metadata.ino(),
        );
        let jailer_descriptor_path = format!("/proc/self/fd/{}", jailer.descriptor());
        let process = CandidateDirectProcess::spawn(
            Path::new(&jailer_descriptor_path),
            &arguments,
            &[],
            Path::new(JAIL_ROOT),
            stdout,
            stderr,
        )?;
        lifecycle.advance(CandidateEvent::Spawned)?;
        let reaped = process.wait_bounded(&deadline, MAXIMUM_OUTPUT_BYTES + 512 * 1024)?;
        if !reaped.status.success() {
            use std::os::unix::process::ExitStatusExt as _;
            return Err(format!(
                "native PROBER jailer direct process failed: signal={:?} code={:?}",
                reaped.status.signal(),
                reaped.status.code()
            )
            .into());
        }
        let events = std::fs::read_to_string(cgroup_path.join("cgroup.events"))?;
        if !events.lines().any(|line| line == "populated 1") {
            return Err("native PROBER expected cgroup was not populated".into());
        }
        if use_seccomp_canary {
            loop {
                let events = std::fs::read_to_string(cgroup_path.join("cgroup.events"))?;
                if events.lines().any(|line| line == "populated 0") {
                    break;
                }
                let remaining = deadline.remaining()?;
                sleep(remaining.min(Duration::from_millis(5)));
            }
            let stderr = std::fs::read_to_string(&stderr_path)?;
            if !stderr
                .lines()
                .filter(|line| line.starts_with("[keep-prober-seccomp]"))
                .eq(["[keep-prober-seccomp] signal=31"])
            {
                return Err("native PROBER seccomp canary signal marker differs".into());
            }
            let cgroup_root =
                PinnedDirectory::open_fixed_kernel_mount(Path::new("/sys/fs/cgroup"))?;
            let keep = cgroup_root.open_child_directory("keep")?;
            let leaf = keep.open_child_directory(&cgroup_leaf_name)?;
            if !leaf
                .read_control("cgroup.events", 4096)?
                .lines()
                .any(|line| line == "populated 0")
                || std::fs::read_dir(&cgroup_path)?.any(|entry| {
                    entry.is_ok_and(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
                })
            {
                return Err("native PROBER seccomp canary cgroup was not exactly empty".into());
            }
            keep.remove_private_directory(&cgroup_leaf_name, leaf.identity())?;
            cgroup_cleanup.active = false;
            drop(jail_cleanup);
            if jail_parent.exists() || uid_has_live_process(lease.uid) {
                return Err("native PROBER seccomp canary residue remains".into());
            }
            return Err("native PROBER seccomp denial canary observed signal=31".into());
        }
        let process_ids = std::fs::read_to_string(cgroup_path.join("cgroup.procs"))?;
        let mut process_count = 0usize;
        let mut containment = None;
        for line in process_ids.lines() {
            let pid = line.parse::<u32>()?;
            process_count += 1;
            let process_root = format!("/proc/{pid}");
            if std::fs::metadata(&process_root)?.uid() != lease.uid
                || std::fs::read_to_string(format!("{process_root}/cgroup"))?
                    != format!("0::/keep/{cgroup_leaf_name}\n")
            {
                return Err("native PROBER cgroup does not own the leased descendant".into());
            }
            containment = Some(observe_live_containment(
                pid,
                lease.uid,
                &jail_guest_root,
                inherited_canary_identity,
            )?);
        }
        if process_count != 1 {
            return Err("native PROBER cgroup does not contain exactly one VMM process".into());
        }
        let mut containment = containment.ok_or("native PROBER containment observation absent")?;
        while containment.seccomp_mode != 2 || containment.seccomp_thread_count < 2 {
            let remaining = deadline.remaining()?;
            sleep(remaining.min(Duration::from_millis(5)));
            containment = observe_live_containment(
                containment.host_pid,
                lease.uid,
                &jail_guest_root,
                inherited_canary_identity,
            )?;
        }
        containment.verify()?;
        let seccomp = CandidateSeccompObservation {
            policy_source_sha256:
                "1b683d5c9fc51174ab1926b84aaf10dc2164678f6c2fe7c38a910556d7b5dc39".into(),
            compiler_sha256: "0a6d20e734f0e6c1d9cf8372fdc478675f301219c141064e4cea9c0582e37cc8"
                .into(),
            compiled_policy_sha256:
                "6a6dfed43d1417a244a999f5bd63679173bf03254dd50f19a9ac4db160c6b0fc".into(),
            target_architecture: "x86_64".into(),
            live_thread_count: containment.seccomp_thread_count,
            filters_per_thread: containment.seccomp_filters_per_thread,
        };
        seccomp.verify()?;
        let landlock = parse_landlock_observation(&std::fs::read(&stderr_path)?)?;
        if std::fs::read(jail_guest_root.join("landlock-denied-canary"))?
            != LANDLOCK_DENIED_CANARY_BYTES
            || jail_guest_root.join("landlock-created-canary").exists()
        {
            return Err("Landlock filesystem denial canary residue differs".into());
        }
        let mut authenticated_result_seen = false;
        let mut last_guest_refusal = None;
        loop {
            let stdout_bytes = std::fs::metadata(&stdout_path)?.len();
            let stderr_bytes = std::fs::metadata(&stderr_path)?.len();
            if stdout_bytes
                .checked_add(stderr_bytes)
                .filter(|total| *total <= MAXIMUM_OUTPUT_BYTES + 512 * 1024)
                .is_none()
            {
                let _ = std::fs::write(cgroup_path.join("cgroup.kill"), b"1\n");
                return Err(CandidateRefusal::OutputLimitExceeded.into());
            }
            let serial = std::fs::read(&stdout_path)?;
            if !authenticated_result_seen {
                match parse_candidate_guest_result(
                    &serial,
                    &fixture.secrets.result_nonce,
                    &fixture.secrets.authentication_key,
                ) {
                    Ok(_) => {
                        authenticated_result_seen = true;
                        // A complete authenticated result is the guest's terminal event.
                        std::fs::write(cgroup_path.join("cgroup.kill"), b"1\n")?;
                    }
                    Err(error) => last_guest_refusal = Some(error),
                }
            }
            if let Ok(events) = std::fs::read_to_string(cgroup_path.join("cgroup.events")) {
                if events.lines().any(|line| line == "populated 0") {
                    if authenticated_result_seen {
                        break;
                    }
                    return Err(CandidateRefusal::GuestResultHeaderAbsent.into());
                }
            }
            let remaining = match deadline.remaining() {
                Ok(remaining) => remaining,
                Err(error) => {
                    let _ = std::fs::write(cgroup_path.join("cgroup.kill"), b"1\n");
                    return Err(last_guest_refusal.unwrap_or(error).into());
                }
            };
            sleep(remaining.min(Duration::from_millis(5)));
        }
        let serial = std::fs::read(&stdout_path)?;
        let guest = match parse_candidate_guest_result(
            &serial,
            &fixture.secrets.result_nonce,
            &fixture.secrets.authentication_key,
        ) {
            Ok(guest) => guest,
            Err(error) => {
                let tail = &serial[serial.len().saturating_sub(2048)..];
                let stderr = std::fs::read(&stderr_path).unwrap_or_default();
                let stderr_tail = &stderr[stderr.len().saturating_sub(2048)..];
                return Err(format!(
                    "{error}; jailerExitSuccess={}; boundedSerialTailHex={}; boundedStderrTailHex={}",
                    reaped.status.success(),
                    bytes_hex(tail),
                    bytes_hex(stderr_tail)
                )
                .into());
            }
        };
        lifecycle.advance(CandidateEvent::GuestResultCaptured)?;
        lifecycle.advance(CandidateEvent::DirectProcessReaped)?;

        let cgroup_root = PinnedDirectory::open_fixed_kernel_mount(Path::new("/sys/fs/cgroup"))?;
        let keep = cgroup_root.open_child_directory("keep")?;
        let leaf = keep.open_child_directory(&cgroup_leaf_name)?;
        let descendants = std::fs::read_dir(&cgroup_path)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .count();
        let observation = CandidateCgroupObservation::parse(
            leaf.read_control("memory.max", 64)?.trim(),
            leaf.read_control("memory.swap.max", 64)?.trim(),
            leaf.read_control("pids.max", 64)?.trim(),
            leaf.read_control("cpu.max", 64)?.trim(),
            leaf.read_control("io.weight", 64)?.trim(),
            &leaf.read_control("cgroup.events", 4096)?,
            descendants,
        )?;
        CandidateCgroupLimits::fixed().verify(&observation)?;
        observation.verify_empty()?;
        lifecycle.advance(CandidateEvent::DescendantsEmpty)?;
        keep.remove_private_directory(&cgroup_leaf_name, leaf.identity())?;
        cgroup_cleanup.active = false;
        drop(jail_cleanup);
        if jail_parent.exists() || uid_has_live_process(lease.uid) {
            return Err("candidate launch residue or leased UID process remains".into());
        }
        lifecycle.advance(CandidateEvent::ResidueRemoved)?;
        lifecycle.advance(CandidateEvent::Complete)?;
        if lifecycle.phase() != CandidatePhase::Complete {
            return Err("candidate lifecycle did not reach complete".into());
        }
        Ok(CandidateRunObservation {
            guest,
            jailer_exit_success: reaped.status.success(),
            containment,
            landlock,
            seccomp,
            cgroup: observation,
        })
    }

    pub fn launch_authenticated_fixture(
        enrollment: &CandidateProbeEnrollment,
        fixture: &ConstructedCandidateFixture,
    ) -> Result<CandidateRunObservation, Box<dyn std::error::Error>> {
        launch_authenticated_fixture_bounded(
            enrollment,
            fixture,
            MAXIMUM_LAUNCH_MILLISECONDS,
            None,
            false,
        )
    }

    pub fn exercise_launch_input_substitution(
        enrollment: &CandidateProbeEnrollment,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for name in [
            "config.json",
            "firecracker",
            "firecracker-vmm",
            "seccomp.bpf",
        ] {
            let fixture = construct_authenticated_fixture(enrollment)?;
            let attempt = fixture.secrets.attempt_id.as_str().to_owned();
            let mut input = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(fixture.root.join(name))?;
            use std::io::Write as _;
            input.write_all(b"substituted\n")?;
            input.sync_all()?;
            drop(input);
            let refused = launch_authenticated_fixture(enrollment, &fixture).is_err();
            drop(fixture);
            let residue = Path::new("/var/lib/keep/native-prober-jails/firecracker")
                .join(&attempt)
                .exists()
                || Path::new("/sys/fs/cgroup/keep").join(&attempt).exists()
                || Path::new("/var/lib/keep/native-prober-candidate")
                    .join(&attempt)
                    .exists();
            if !refused || residue {
                return Err(format!(
                    "launch input substitution for {name} was not refused without residue"
                )
                .into());
            }
        }
        Ok(())
    }

    pub fn exercise_malformed_shim_handoff(
        enrollment: &CandidateProbeEnrollment,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = construct_authenticated_fixture(enrollment)?;
        let attempt = fixture.secrets.attempt_id.as_str().to_owned();
        let refused = launch_authenticated_fixture_bounded(
            enrollment,
            &fixture,
            MAXIMUM_LAUNCH_MILLISECONDS,
            Some("--api-sock"),
            false,
        )
        .is_err();
        let stderr = std::fs::read_to_string(fixture.root.join("jailer-stderr"))?;
        let exact_refusal = stderr
            .lines()
            .filter(|line| line.starts_with("[keep-prober-landlock]"))
            .eq(["[keep-prober-landlock] REFUSED post-jailer VMM argument contract refused"]);
        drop(fixture);
        let residue = Path::new("/var/lib/keep/native-prober-jails/firecracker")
            .join(&attempt)
            .exists()
            || Path::new("/sys/fs/cgroup/keep").join(&attempt).exists()
            || Path::new("/var/lib/keep/native-prober-candidate")
                .join(&attempt)
                .exists();
        if !refused || !exact_refusal || residue {
            return Err("malformed post-jailer handoff was not refused without residue".into());
        }
        Ok(())
    }

    pub fn exercise_seccomp_denial_canary(
        enrollment: &CandidateProbeEnrollment,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = construct_authenticated_fixture(enrollment)?;
        let attempt = fixture.secrets.attempt_id.as_str().to_owned();
        // x86_64 Linux SIGSYS is 31. The canary admits only process exit, so
        // Firecracker's first required post-install syscall must be trapped.
        let result = launch_authenticated_fixture_bounded(
            enrollment,
            &fixture,
            MAXIMUM_LAUNCH_MILLISECONDS,
            None,
            true,
        );
        let detail = result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unexpected candidate success".into());
        let stderr = std::fs::read_to_string(fixture.root.join("jailer-stderr"))?;
        let trapped = stderr
            .lines()
            .filter(|line| line.starts_with("[keep-prober-seccomp]"))
            .eq(["[keep-prober-seccomp] signal=31"]);
        drop(fixture);
        let residue = Path::new("/var/lib/keep/native-prober-jails/firecracker")
            .join(&attempt)
            .exists()
            || Path::new("/sys/fs/cgroup/keep").join(&attempt).exists()
            || Path::new("/var/lib/keep/native-prober-candidate")
                .join(&attempt)
                .exists();
        if !trapped || residue {
            return Err(format!(
                "measured seccomp denial canary was not trapped and cleaned exactly: {detail}"
            )
            .into());
        }
        Ok(())
    }

    pub fn exercise_wrong_authentication_timeout(
        enrollment: &CandidateProbeEnrollment,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = construct_authenticated_fixture(enrollment)?;
        let attempt = fixture.secrets.attempt_id.as_str().to_owned();
        fixture.secrets.authentication_key[0] ^= 1;
        let refused =
            launch_authenticated_fixture_bounded(enrollment, &fixture, 2_000, None, false)
                .is_err_and(|error| {
                    error.to_string()
                        == CandidateRefusal::GuestResultAuthenticationFailed.to_string()
                });
        drop(fixture);
        let residue = Path::new("/var/lib/keep/native-prober-jails/firecracker")
            .join(&attempt)
            .exists()
            || Path::new("/sys/fs/cgroup/keep").join(&attempt).exists()
            || Path::new("/var/lib/keep/native-prober-candidate")
                .join(&attempt)
                .exists();
        if !refused || residue {
            return Err("wrong authenticated frame was not rejected and cleaned exactly".into());
        }
        Ok(())
    }

    pub fn exercise_guest_output_overflow(
        enrollment: &CandidateProbeEnrollment,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = construct_authenticated_fixture_with_request(
            enrollment,
            b"#!/bin/sh\nset -eu\nhead -c 2097152 /dev/zero\n",
        )?;
        let attempt = fixture.secrets.attempt_id.as_str().to_owned();
        let observation = launch_authenticated_fixture(enrollment, &fixture)?;
        let bounded = observation.guest.exit_code == 125
            && observation.guest.stdout.len() as u64 == MAXIMUM_OUTPUT_BYTES
            && observation.guest.stderr.len() as u64 <= MAXIMUM_OUTPUT_BYTES;
        drop(fixture);
        let residue = Path::new("/var/lib/keep/native-prober-jails/firecracker")
            .join(&attempt)
            .exists()
            || Path::new("/sys/fs/cgroup/keep").join(&attempt).exists()
            || Path::new("/var/lib/keep/native-prober-candidate")
                .join(&attempt)
                .exists();
        if !bounded || residue {
            return Err("guest output overflow was not bounded and cleaned exactly".into());
        }
        Ok(())
    }

    pub fn exercise_zero_guest_network_devices(
        enrollment: &CandidateProbeEnrollment,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = construct_authenticated_fixture_with_request(
            enrollment,
            b"#!/bin/sh\nset -eu\nentries=$(ls -1 /sys/class/net | tr '\\n' ' ')\n[ \"$entries\" = \"lo \" ]\n[ ! -e /sys/class/net/eth0 ]\nprintf 'ok 1 - no-guest-network-device\\n'\n",
        )?;
        let attempt = fixture.secrets.attempt_id.as_str().to_owned();
        let observation = launch_authenticated_fixture(enrollment, &fixture)?;
        let denied = observation.guest.exit_code == 0
            && observation.guest.stdout == "ok 1 - no-guest-network-device\n"
            && observation.containment.socket_descriptors_absent;
        drop(fixture);
        let residue = Path::new("/var/lib/keep/native-prober-jails/firecracker")
            .join(&attempt)
            .exists()
            || Path::new("/sys/fs/cgroup/keep").join(&attempt).exists()
            || Path::new("/var/lib/keep/native-prober-candidate")
                .join(&attempt)
                .exists();
        if !denied || residue {
            return Err("guest network device or live VMM socket was present".into());
        }
        Ok(())
    }

    /// Deliberate test-only enrollment token. It carries no path, descriptor, signature,
    /// deployment, lease, or production brand and cannot be constructed without the feature.
    #[derive(Debug)]
    pub struct CandidateProbeEnrollment {
        _private: (),
    }

    pub fn enroll_repository_fixture() -> CandidateProbeEnrollment {
        CandidateProbeEnrollment { _private: () }
    }

    /// Exercises only a fixed, non-authorizing host fixture. This is replaced by the captured
    /// Firecracker candidate once its complete staging transaction is joined.
    pub fn exercise_bounded_host_fixture(
        _enrollment: &CandidateProbeEnrollment,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "keep-native-launch-candidate-{}-{nonce}",
            std::process::id()
        ));
        create_dir(&root)?;
        let cleanup = CandidateFixtureRoot(root.clone());
        let open = |name| {
            OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(root.join(name))
        };
        let stdout = open("stdout")?;
        let stderr = open("stderr")?;
        let process = CandidateDirectProcess::spawn(
            Path::new("/usr/bin/true"),
            &[],
            &[],
            &root,
            stdout,
            stderr,
        )?;
        let result = process.wait_bounded(&CandidateDeadline::start(1_000)?, 0)?;
        let valid = result.status.success() && result.stdout_bytes == 0 && result.stderr_bytes == 0;
        std::fs::remove_dir_all(&root)?;
        drop(cleanup);
        if !valid {
            return Err(CandidateRefusal::DirectProcessFailed.into());
        }
        Ok(())
    }

    /// Creates, verifies, kills, and removes one real cgroup-v2 leaf without launching authority.
    pub fn exercise_cgroup_v2_fixture(
        enrollment: &CandidateProbeEnrollment,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _ = enrollment;
        const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
        let root = PinnedDirectory::open_fixed_kernel_mount(Path::new("/sys/fs/cgroup"))?;
        let filesystem = root.filesystem_identity()?;
        if filesystem.filesystem_type != CGROUP2_SUPER_MAGIC
            || filesystem.read_only
            || root.identity().uid != 0
            || root.identity().gid != 0
        {
            return Err(CandidateRefusal::CgroupLimitMismatch.into());
        }
        let parent = match root.create_private_directory("keep") {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                root.open_child_directory("keep")?
            }
            Err(error) => return Err(error.into()),
        };
        if parent.identity().uid != 0
            || parent.identity().gid != 0
            || parent.identity().mode & 0o077 != 0
        {
            return Err(CandidateRefusal::CgroupLimitMismatch.into());
        }
        parent.write_control("cgroup.subtree_control", b"+cpu +io +memory +pids\n")?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let leaf_name = format!("candidate-{}-{nonce}", std::process::id());
        let leaf = parent.create_private_directory(&leaf_name)?;
        struct LeafCleanup<'a> {
            parent: &'a PinnedDirectory,
            leaf: &'a PinnedDirectory,
            name: &'a str,
        }
        impl Drop for LeafCleanup<'_> {
            fn drop(&mut self) {
                let _ = self.leaf.write_control("cgroup.kill", b"1\n");
                let _ = self
                    .parent
                    .remove_private_directory(self.name, self.leaf.identity());
            }
        }
        let cleanup = LeafCleanup {
            parent: &parent,
            leaf: &leaf,
            name: &leaf_name,
        };
        let limits = CandidateCgroupLimits::fixed();
        for (name, value) in [
            ("memory.max", limits.memory_max.to_string()),
            ("memory.swap.max", limits.memory_swap_max.to_string()),
            ("pids.max", limits.pids_max.to_string()),
            ("cpu.max", limits.cpu_max.to_owned()),
            ("io.weight", CGROUP_IO_WEIGHT_WRITE.to_owned()),
        ] {
            leaf.write_control(name, format!("{value}\n").as_bytes())?;
        }
        let observation = CandidateCgroupObservation::parse(
            leaf.read_control("memory.max", 64)?.trim(),
            leaf.read_control("memory.swap.max", 64)?.trim(),
            leaf.read_control("pids.max", 64)?.trim(),
            leaf.read_control("cpu.max", 64)?.trim(),
            leaf.read_control("io.weight", 64)?.trim(),
            &leaf.read_control("cgroup.events", 4096)?,
            0,
        )?;
        limits.verify(&observation)?;
        observation.verify_empty()?;
        drop(cleanup);
        match parent.open_child_directory(&leaf_name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(CandidateRefusal::CgroupHasDescendants.into()),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{OpenOptions, create_dir};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn process_scratch() -> (std::path::PathBuf, File, File) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "keep-prober-process-{}-{nonce}",
            std::process::id()
        ));
        create_dir(&root).unwrap();
        let output = |name| {
            OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(root.join(name))
                .unwrap()
        };
        let stdout = output("stdout");
        let stderr = output("stderr");
        (root, stdout, stderr)
    }

    #[test]
    fn success_requires_result_reap_empty_descendants_and_residue_removal_in_order() {
        let mut lifecycle = CandidateLifecycle::prepared();
        for (event, phase) in [
            (CandidateEvent::Spawned, CandidatePhase::Spawned),
            (
                CandidateEvent::GuestResultCaptured,
                CandidatePhase::GuestResultCaptured,
            ),
            (
                CandidateEvent::DirectProcessReaped,
                CandidatePhase::DirectProcessReaped,
            ),
            (
                CandidateEvent::DescendantsEmpty,
                CandidatePhase::DescendantsEmpty,
            ),
            (
                CandidateEvent::ResidueRemoved,
                CandidatePhase::ResidueRemoved,
            ),
            (CandidateEvent::Complete, CandidatePhase::Complete),
        ] {
            lifecycle.advance(event).unwrap();
            assert_eq!(lifecycle.phase(), phase);
        }
        assert!(lifecycle.advance(CandidateEvent::Abort).is_err());
    }

    #[test]
    fn every_skipped_or_reordered_success_transition_refuses() {
        for event in [
            CandidateEvent::GuestResultCaptured,
            CandidateEvent::DirectProcessReaped,
            CandidateEvent::DescendantsEmpty,
            CandidateEvent::ResidueRemoved,
            CandidateEvent::Complete,
        ] {
            let mut lifecycle = CandidateLifecycle::prepared();
            assert!(lifecycle.advance(event).is_err(), "accepted {event:?}");
            assert_eq!(lifecycle.phase(), CandidatePhase::Prepared);
        }
    }

    #[test]
    fn abort_is_terminal_and_never_becomes_success() {
        for initial_event in [None, Some(CandidateEvent::Spawned)] {
            let mut lifecycle = CandidateLifecycle::prepared();
            if let Some(event) = initial_event {
                lifecycle.advance(event).unwrap();
            }
            lifecycle.advance(CandidateEvent::Abort).unwrap();
            assert_eq!(lifecycle.phase(), CandidatePhase::Aborted);
            for event in [
                CandidateEvent::Spawned,
                CandidateEvent::GuestResultCaptured,
                CandidateEvent::DirectProcessReaped,
                CandidateEvent::DescendantsEmpty,
                CandidateEvent::ResidueRemoved,
                CandidateEvent::Complete,
                CandidateEvent::Abort,
            ] {
                assert!(lifecycle.advance(event).is_err());
            }
        }
    }

    #[test]
    fn attempt_identity_is_closed_and_jailer_policy_has_no_optional_surface() {
        let nonce = "0123456789abcdef".repeat(2);
        let attempt = CandidateAttemptId::from_nonce_hex(&nonce).unwrap();
        assert_eq!(attempt.as_str(), format!("keep-{nonce}"));
        for invalid in [
            "",
            &"A".repeat(32),
            &"0".repeat(31),
            &format!("{}g", "0".repeat(31)),
        ] {
            assert_eq!(
                CandidateAttemptId::from_nonce_hex(invalid),
                Err(CandidateRefusal::InvalidAttemptId)
            );
        }
        let arguments = fixed_jailer_arguments(&attempt, 200_123);
        assert!(arguments.windows(2).any(|pair| pair == ["--", "--no-api"]));
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("net") || argument.contains("api-sock"))
        );
        assert!(arguments.contains(&"memory.swap.max=0".to_owned()));
    }

    #[test]
    fn cgroup_observation_requires_exact_limits_and_complete_emptiness() {
        let limits = CandidateCgroupLimits::fixed();
        let empty = CandidateCgroupObservation::parse(
            &HOST_MEMORY_BYTES.to_string(),
            "0",
            &MAXIMUM_PIDS.to_string(),
            CGROUP_CPU_MAX,
            CGROUP_IO_WEIGHT,
            "populated 0\nfrozen 0\n",
            0,
        )
        .unwrap();
        limits.verify(&empty).unwrap();
        empty.verify_empty().unwrap();
        let populated = CandidateCgroupObservation {
            populated: true,
            ..empty.clone()
        };
        assert_eq!(
            populated.verify_empty(),
            Err(CandidateRefusal::CgroupStillPopulated)
        );
        let descendants = CandidateCgroupObservation {
            descendant_directories: 1,
            ..empty.clone()
        };
        assert_eq!(
            descendants.verify_empty(),
            Err(CandidateRefusal::CgroupHasDescendants)
        );
        let wrong = CandidateCgroupObservation {
            pids_max: MAXIMUM_PIDS + 1,
            ..empty
        };
        assert_eq!(
            limits.verify(&wrong),
            Err(CandidateRefusal::CgroupLimitMismatch)
        );
    }

    #[cfg(feature = "candidate-probe")]
    #[test]
    fn live_containment_observation_refuses_every_security_neuter() {
        let valid = candidate_probe::CandidateLiveContainmentObservation {
            host_pid: 42,
            uid: 300_123,
            seccomp_mode: 2,
            seccomp_thread_count: 3,
            seccomp_filters_per_thread: 1,
            pid_namespace_isolated: true,
            mount_namespace_isolated: true,
            chroot_matches_jail: true,
            capabilities_empty: true,
            socket_descriptors_absent: true,
            environment_empty: true,
            inherited_descriptor_absent: true,
        };
        valid.verify().unwrap();
        for mutant in [
            candidate_probe::CandidateLiveContainmentObservation {
                host_pid: 0,
                ..valid.clone()
            },
            candidate_probe::CandidateLiveContainmentObservation {
                uid: 200_123,
                ..valid.clone()
            },
            candidate_probe::CandidateLiveContainmentObservation {
                seccomp_mode: 0,
                ..valid.clone()
            },
            candidate_probe::CandidateLiveContainmentObservation {
                seccomp_thread_count: 1,
                ..valid.clone()
            },
            candidate_probe::CandidateLiveContainmentObservation {
                seccomp_filters_per_thread: 0,
                ..valid.clone()
            },
            candidate_probe::CandidateLiveContainmentObservation {
                pid_namespace_isolated: false,
                ..valid.clone()
            },
            candidate_probe::CandidateLiveContainmentObservation {
                mount_namespace_isolated: false,
                ..valid.clone()
            },
            candidate_probe::CandidateLiveContainmentObservation {
                chroot_matches_jail: false,
                ..valid.clone()
            },
            candidate_probe::CandidateLiveContainmentObservation {
                capabilities_empty: false,
                ..valid.clone()
            },
            candidate_probe::CandidateLiveContainmentObservation {
                socket_descriptors_absent: false,
                ..valid.clone()
            },
            candidate_probe::CandidateLiveContainmentObservation {
                environment_empty: false,
                ..valid.clone()
            },
            candidate_probe::CandidateLiveContainmentObservation {
                inherited_descriptor_absent: false,
                ..valid.clone()
            },
        ] {
            assert!(mutant.verify().is_err());
        }
    }

    #[cfg(feature = "candidate-probe")]
    #[test]
    fn seccomp_policy_evidence_refuses_every_measurement_neuter() {
        let valid = candidate_probe::CandidateSeccompObservation {
            policy_source_sha256:
                "1b683d5c9fc51174ab1926b84aaf10dc2164678f6c2fe7c38a910556d7b5dc39".into(),
            compiler_sha256: "0a6d20e734f0e6c1d9cf8372fdc478675f301219c141064e4cea9c0582e37cc8"
                .into(),
            compiled_policy_sha256:
                "6a6dfed43d1417a244a999f5bd63679173bf03254dd50f19a9ac4db160c6b0fc".into(),
            target_architecture: "x86_64".into(),
            live_thread_count: 3,
            filters_per_thread: 1,
        };
        valid.verify().unwrap();
        for mutant in [
            candidate_probe::CandidateSeccompObservation {
                policy_source_sha256: "00".repeat(32),
                ..valid.clone()
            },
            candidate_probe::CandidateSeccompObservation {
                compiler_sha256: "00".repeat(32),
                ..valid.clone()
            },
            candidate_probe::CandidateSeccompObservation {
                compiled_policy_sha256: "00".repeat(32),
                ..valid.clone()
            },
            candidate_probe::CandidateSeccompObservation {
                target_architecture: "aarch64".into(),
                ..valid.clone()
            },
            candidate_probe::CandidateSeccompObservation {
                live_thread_count: 1,
                ..valid.clone()
            },
            candidate_probe::CandidateSeccompObservation {
                filters_per_thread: 0,
                ..valid.clone()
            },
        ] {
            assert!(mutant.verify().is_err());
        }
    }

    #[cfg(feature = "candidate-probe")]
    #[test]
    fn landlock_marker_is_exact_and_every_observed_control_is_load_bearing() {
        let expected = reviewed_landlock_policy(4).unwrap();
        let marker = format!(
            "noise\n[keep-prober-landlock] abi=4 fs={:x} net={:x} scoped={:x} deniedWrite=13 deniedCreate=13\n",
            expected.handled_filesystem, expected.handled_network, expected.scoped
        );
        let valid = candidate_probe::parse_landlock_observation(marker.as_bytes()).unwrap();
        valid.verify().unwrap();
        for mutant in [
            candidate_probe::CandidateLandlockObservation {
                abi: 3,
                ..valid.clone()
            },
            candidate_probe::CandidateLandlockObservation {
                handled_filesystem: valid.handled_filesystem ^ 1,
                ..valid.clone()
            },
            candidate_probe::CandidateLandlockObservation {
                handled_network: valid.handled_network ^ 1,
                ..valid.clone()
            },
            candidate_probe::CandidateLandlockObservation {
                scoped: 1,
                ..valid.clone()
            },
            candidate_probe::CandidateLandlockObservation {
                denied_write_errno: 0,
                ..valid.clone()
            },
            candidate_probe::CandidateLandlockObservation {
                denied_create_errno: 0,
                ..valid.clone()
            },
        ] {
            assert!(mutant.verify().is_err());
        }
        assert!(candidate_probe::parse_landlock_observation(marker.repeat(2).as_bytes()).is_err());
        assert!(
            candidate_probe::parse_landlock_observation(marker.replace("fs=7", "fs=07").as_bytes())
                .is_err()
        );
        assert!(
            candidate_probe::parse_landlock_observation(
                marker.replace("abi=4", "abi=11").as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn cgroup_parser_refuses_ambiguous_or_noncanonical_values() {
        for (memory, events) in [
            ("max", "populated 0\n"),
            ("01", "populated\t0\n"),
            ("1", "populated 2\n"),
            ("1", ""),
        ] {
            assert!(
                CandidateCgroupObservation::parse(
                    memory,
                    "0",
                    "128",
                    CGROUP_CPU_MAX,
                    CGROUP_IO_WEIGHT,
                    events,
                    0
                )
                .is_err()
            );
        }
    }

    #[test]
    fn monotonic_deadline_refuses_zero_and_above_the_frozen_ceiling() {
        assert!(matches!(
            CandidateDeadline::start(0),
            Err(CandidateRefusal::DeadlineOutOfRange)
        ));
        assert!(matches!(
            CandidateDeadline::start(MAXIMUM_LAUNCH_MILLISECONDS + 1),
            Err(CandidateRefusal::DeadlineOutOfRange)
        ));
        assert!(
            CandidateDeadline::start(1_000)
                .unwrap()
                .remaining()
                .unwrap()
                <= Duration::from_millis(1_000)
        );
    }

    #[test]
    fn direct_process_has_empty_environment_bounded_output_and_is_reaped() {
        let (root, stdout, stderr) = process_scratch();
        let arguments = vec![
            "-c".to_owned(),
            "test -z \"${HOME+x}\" && printf exact && printf err >&2".to_owned(),
        ];
        let process = CandidateDirectProcess::spawn(
            Path::new("/bin/sh"),
            &arguments,
            &[],
            &root,
            stdout,
            stderr,
        )
        .unwrap();
        let result = process
            .wait_bounded(&CandidateDeadline::start(1_000).unwrap(), 64)
            .unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout_bytes, 5);
        assert_eq!(result.stderr_bytes, 3);
        assert_eq!(std::fs::read(root.join("stdout")).unwrap(), b"exact");
        assert_eq!(std::fs::read(root.join("stderr")).unwrap(), b"err");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn direct_process_timeout_and_output_overflow_kill_and_reap() {
        let (timeout_root, stdout, stderr) = process_scratch();
        let timeout = CandidateDirectProcess::spawn(
            Path::new("/bin/sh"),
            &["-c".to_owned(), "exec sleep 30".to_owned()],
            &[],
            &timeout_root,
            stdout,
            stderr,
        )
        .unwrap()
        .wait_bounded(&CandidateDeadline::start(10).unwrap(), 64);
        assert_eq!(timeout.unwrap_err(), CandidateRefusal::DeadlineExpired);
        std::fs::remove_dir_all(timeout_root).unwrap();

        let (overflow_root, stdout, stderr) = process_scratch();
        let overflow = CandidateDirectProcess::spawn(
            Path::new("/bin/sh"),
            &["-c".to_owned(), "printf 123456789".to_owned()],
            &[],
            &overflow_root,
            stdout,
            stderr,
        )
        .unwrap()
        .wait_bounded(&CandidateDeadline::start(1_000).unwrap(), 4);
        assert_eq!(overflow.unwrap_err(), CandidateRefusal::OutputLimitExceeded);
        std::fs::remove_dir_all(overflow_root).unwrap();
    }

    fn typescript_guest_frame_golden() -> Vec<u8> {
        let hex = "4b4545505f524553554c545f5631203031323334353637383961626364656630313233343536373839616263646566203720313220342062323438656165326466313639396438653461653938386338333337316666393338343162303765333239373038653864613264613865396236346663376466206161363339323565646632323565323664373965636139636562633736333964653664666535373664326439653431383365313632663939653338626537656520653332316532316633353936663661356538653766626333303765303665656164613365353631333634393635623564333661343035393230343666303930640a6f6b2031202d207265616c0a7761726e0a4b4545505f524553554c545f454e445f56312030313233343536373839616263646566303132333435363738396162636465660a";
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn authenticated_guest_parser_matches_independent_typescript_golden() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let key = [0x5au8; 32];
        let mut serial = b"boot\n".to_vec();
        serial.extend_from_slice(&typescript_guest_frame_golden());
        serial.extend_from_slice(b"Power down\n");
        let result = parse_candidate_guest_result(&serial, nonce, &key).unwrap();
        assert_eq!(result.exit_code, 7);
        assert_eq!(result.stdout, "ok 1 - real\n");
        assert_eq!(result.stderr, "warn");
        let empty_stderr_hex = "4b4545505f524553554c545f5631203031323334353637383961626364656630313233343536373839616263646566203020333120302039363233646165396439393862353965663764363230656561313439353633303634343738643964636566323436383166386133623336343963613234616135206533623063343432393866633163313439616662663463383939366662393234323761653431653436343962393334636134393539393162373835326238353520643262373866346462303664326636326336633736313530613334363462316262663934323534343434643639343031633766313132386532306331393964300a6f6b2031202d206e61746976652d70726f6265722d63616e6469646174650a0a4b4545505f524553554c545f454e445f56312030313233343536373839616263646566303132333435363738396162636465660a";
        let empty_stderr = empty_stderr_hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        let parsed = parse_candidate_guest_result(&empty_stderr, nonce, &key).unwrap();
        assert_eq!(parsed.stdout, "ok 1 - native-prober-candidate\n");
        assert_eq!(parsed.stderr, "");
    }

    #[test]
    fn authenticated_guest_parser_refuses_mutation_replay_and_truncation() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let key = [0x5au8; 32];
        let frame = typescript_guest_frame_golden();
        for removed in 1..=48 {
            assert!(
                parse_candidate_guest_result(&frame[..frame.len() - removed], nonce, &key).is_err()
            );
        }
        let mut mutated = frame.clone();
        let payload = mutated
            .windows(4)
            .position(|window| window == b"ok 1")
            .unwrap();
        mutated[payload] ^= 1;
        assert_eq!(
            parse_candidate_guest_result(&mutated, nonce, &key),
            Err(CandidateRefusal::GuestResultDigestMismatch)
        );
        let mut replay = frame.clone();
        replay.extend_from_slice(&frame);
        assert!(parse_candidate_guest_result(&replay, nonce, &key).is_err());
        assert_eq!(
            parse_candidate_guest_result(&frame, nonce, &[0x5bu8; 32]),
            Err(CandidateRefusal::GuestResultAuthenticationFailed)
        );
    }

    #[test]
    fn candidate_secrets_are_kernel_minted_separate_and_hmac_ready() {
        let first = mint_candidate_fixture_secrets().unwrap();
        let second = mint_candidate_fixture_secrets().unwrap();
        assert_ne!(first.attempt_id, second.attempt_id);
        assert_ne!(first.result_nonce, second.result_nonce);
        assert_ne!(first.authentication_key, second.authentication_key);
        assert!(lowercase_hex(
            first.attempt_id.as_str().strip_prefix("keep-").unwrap(),
            32
        ));
        assert!(lowercase_hex(&first.result_nonce, 32));
        for index in 0..32 {
            assert_eq!(
                first.authentication_ipad[index],
                first.authentication_key[index] ^ 0x36
            );
            assert_eq!(
                first.authentication_opad[index],
                first.authentication_key[index] ^ 0x5c
            );
        }
        assert!(
            first.authentication_ipad[32..]
                .iter()
                .all(|byte| *byte == 0x36)
        );
        assert!(
            first.authentication_opad[32..]
                .iter()
                .all(|byte| *byte == 0x5c)
        );
    }

    #[test]
    fn firecracker_config_is_closed_zero_network_and_matches_frozen_limits() {
        let config = String::from_utf8(fixed_firecracker_config()).unwrap();
        assert!(config.ends_with("\n"));
        assert!(config.contains("\"vcpu_count\":1"));
        assert!(config.contains("\"mem_size_mib\":256"));
        assert!(config.contains("pci=off"));
        assert!(config.contains("\"is_read_only\":true"));
        for forbidden in [
            "network-interfaces",
            "vsock",
            "balloon",
            "mmds",
            "snapshot",
            "api-sock",
        ] {
            assert!(!config.contains(forbidden), "config admitted {forbidden}");
        }
        assert_eq!(
            CANDIDATE_REQUEST_SCRIPT,
            b"#!/bin/sh\nset -eu\nprintf 'ok 1 - native-prober-candidate\\n'\n"
        );
    }
}
