#![cfg(target_os = "linux")]

//! The narrowly reviewed Linux syscall boundary for Keep native isolation.
//! No policy or authority decision belongs in this crate.
//! The production root/data primitives require Linux 6.8 or newer for unique mount IDs;
//! this also subsumes the Linux 6.3 floor for non-executable memfd seals.

use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const RESOLUTION_FLAGS: u64 = libc::RESOLVE_BENEATH
    | libc::RESOLVE_NO_SYMLINKS
    | libc::RESOLVE_NO_MAGICLINKS
    | libc::RESOLVE_NO_XDEV;
pub const ROOT_RESOLUTION_FLAGS: u64 =
    libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
pub const REQUIRED_MEMFD_SEALS: i32 =
    libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
pub const REQUIRED_DATA_MEMFD_SEALS: i32 = REQUIRED_MEMFD_SEALS | 0x0020;
const MFD_EXEC: u32 = 0x0010;
const MFD_NOEXEC_SEAL: u32 = 0x0008;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
const LANDLOCK_ACCESS_FS_RESOLVE_UNIX: u64 = 1 << 16;
const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
const LANDLOCK_ACCESS_NET_BIND_UDP: u64 = 1 << 2;
const LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP: u64 = 1 << 3;
const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;
pub const MAXIMUM_SUPPORTED_LANDLOCK_ABI: u32 = 10;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_ARGUMENT_ZERO_OFFSET: u32 = 16;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const STATX_MNT_ID_UNIQUE: u32 = 0x0000_4000;

#[repr(C)]
struct StatxTimestamp {
    seconds: i64,
    nanoseconds: u32,
    reserved: i32,
}

#[repr(C)]
struct Statx {
    mask: u32,
    block_size: u32,
    attributes: u64,
    hard_links: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    reserved_zero: u16,
    inode: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    accessed: StatxTimestamp,
    created: StatxTimestamp,
    changed: StatxTimestamp,
    modified: StatxTimestamp,
    device_major: u32,
    device_minor: u32,
    containing_device_major: u32,
    containing_device_minor: u32,
    mount_id: u64,
    direct_io_memory_alignment: u32,
    direct_io_offset_alignment: u32,
    subvolume: u64,
    atomic_write_unit_min: u32,
    atomic_write_unit_max: u32,
    atomic_write_segments_max: u32,
    direct_io_read_offset_alignment: u32,
    spare: [u64; 9],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub links: u64,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemIdentity {
    pub mount_id: u64,
    pub filesystem_type: u64,
    pub read_only: bool,
}

impl FileIdentity {
    fn capture(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[derive(Debug)]
pub struct CapturedRegularFile {
    file: File,
    bytes: Vec<u8>,
    identity: FileIdentity,
}

/// Machine-readable acquisition failures. This is filesystem evidence, not a
/// grant of authority; existing io::Result callers retain their error contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureIoFailure {
    Path,
    Type,
    Limit,
    Race,
    Unsupported,
}

impl std::fmt::Display for CaptureIoFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Path => "capture path refused",
            Self::Type => "capture type or link count refused",
            Self::Limit => "capture allocation or size limit",
            Self::Race => "capture inode changed",
            Self::Unsupported => "capture descriptor confinement unavailable",
        })
    }
}
impl std::error::Error for CaptureIoFailure {}

impl CaptureIoFailure {
    /// Keep errno interpretation inside the Linux boundary. Unknown I/O errors
    /// remain unknown rather than being retried or mislabeled as safe fallback.
    pub fn from_io(error: &io::Error) -> Option<Self> {
        if let Some(failure) = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<Self>())
        {
            return Some(*failure);
        }
        match error.raw_os_error() {
            Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL) => Some(Self::Unsupported),
            Some(libc::ELOOP | libc::EXDEV | libc::ENAMETOOLONG | libc::ENOTDIR) => {
                Some(Self::Path)
            }
            Some(libc::EISDIR) => Some(Self::Type),
            Some(libc::EFBIG | libc::ENOMEM | libc::EMFILE | libc::ENFILE) => Some(Self::Limit),
            Some(libc::ESTALE | libc::EAGAIN) => Some(Self::Race),
            _ => None,
        }
    }
}

fn capture_error(failure: CaptureIoFailure) -> io::Error {
    io::Error::new(
        if failure == CaptureIoFailure::Unsupported {
            io::ErrorKind::Unsupported
        } else {
            io::ErrorKind::InvalidData
        },
        failure,
    )
}

#[derive(Debug)]
pub struct PinnedRegularFile {
    file: File,
    identity: FileIdentity,
}

impl PinnedRegularFile {
    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub fn descriptor(&self) -> i32 {
        self.file.as_raw_fd()
    }

    pub fn read_bounded_chunks<F>(&self, maximum_bytes: u64, mut consume: F) -> io::Result<u64>
    where
        F: FnMut(&[u8]) -> io::Result<()>,
    {
        if maximum_bytes == 0 || self.identity.size > maximum_bytes {
            return Err(invalid("pinned file exceeds streaming read bound"));
        }
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let before = FileIdentity::capture(&file.metadata()?);
        if before != self.identity {
            return Err(invalid(
                "pinned file identity changed before streaming read",
            ));
        }
        let mut total = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .filter(|value| *value <= maximum_bytes)
                .ok_or_else(|| invalid("pinned streaming read exceeds bound"))?;
            consume(&buffer[..count])?;
        }
        if total != self.identity.size || FileIdentity::capture(&file.metadata()?) != before {
            return Err(invalid(
                "pinned file identity or length changed during streaming read",
            ));
        }
        Ok(total)
    }
}

impl CapturedRegularFile {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub fn descriptor(&self) -> i32 {
        self.file.as_raw_fd()
    }

    /// Transfers the already captured buffer without copying or reopening its path.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug)]
pub struct PinnedDirectory {
    directory: File,
    identity: FileIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntryIdentity {
    pub name: String,
    pub identity: FileIdentity,
}

struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: successful fdopendir transferred one duplicated FD to this
        // stream, which is closed once. The original directory FD stays owned.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

#[derive(Debug)]
pub struct SealedExecutable {
    file: File,
    byte_length: u64,
}

#[derive(Debug)]
pub struct SealedFile {
    file: File,
    byte_length: u64,
}

/// Stable identity for one Linux process incarnation. PID numbers are never used for signaling
/// after this handle is acquired.
#[derive(Debug)]
pub struct ProcessIdentity {
    file: File,
    pid: u32,
}

impl ProcessIdentity {
    pub fn open(pid: u32) -> io::Result<Self> {
        let pid = i32::try_from(pid).map_err(|_| invalid("PID exceeds signed kernel range"))?;
        if pid <= 0 {
            return Err(invalid("PID must identify a userspace process"));
        }
        // SAFETY: pidfd_open takes only the validated positive PID and zero flags. A successful
        // return is a fresh CLOEXEC descriptor referring to that exact process incarnation.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful pidfd_open returned a fresh descriptor owned exactly once here.
        let file = File::from(unsafe { OwnedFd::from_raw_fd(raw as i32) });
        Ok(Self {
            file,
            pid: pid as u32,
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn has_exited(&self) -> io::Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd for the live owned pidfd; zero
        // timeout performs a nonblocking readiness observation and writes only revents.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(invalid("pidfd became invalid"));
        }
        Ok(ready == 1 && descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }

    pub fn terminate(&self) -> io::Result<()> {
        self.send_signal(libc::SIGTERM)
    }

    pub fn kill(&self) -> io::Result<()> {
        self.send_signal(libc::SIGKILL)
    }

    fn send_signal(&self, signal: i32) -> io::Result<()> {
        if signal != libc::SIGKILL && signal != libc::SIGTERM {
            return Err(invalid("process signal is outside the closed teardown set"));
        }
        // SAFETY: the owned pidfd identifies the exact process incarnation; siginfo is null and
        // flags are zero as required for an ordinary SIGTERM/SIGKILL delivery.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.file.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[derive(Debug)]
pub struct LandlockRuleset {
    file: File,
    observation: LandlockPolicyObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LandlockPolicyObservation {
    pub abi: u32,
    pub handled_filesystem: u64,
    pub handled_network: u64,
    pub scoped: u64,
}

pub fn reviewed_landlock_policy(abi: u32) -> io::Result<LandlockPolicyObservation> {
    if !(3..=MAXIMUM_SUPPORTED_LANDLOCK_ABI).contains(&abi) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Landlock ABI is outside Keep's reviewed range",
        ));
    }
    let mut handled_filesystem = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_REFER
        | LANDLOCK_ACCESS_FS_TRUNCATE;
    if abi >= 5 {
        handled_filesystem |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    if abi >= 9 {
        handled_filesystem |= LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
    }
    let mut handled_network = 0;
    if abi >= 4 {
        handled_network |= LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
    }
    if abi >= 10 {
        handled_network |= LANDLOCK_ACCESS_NET_BIND_UDP | LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP;
    }
    let scoped = if abi >= 6 {
        LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL
    } else {
        0
    };
    Ok(LandlockPolicyObservation {
        abi,
        handled_filesystem,
        handled_network,
        scoped,
    })
}

impl LandlockRuleset {
    pub fn new(minimum_abi: u32) -> io::Result<Self> {
        let abi = landlock_abi_version()?;
        if abi < minimum_abi {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Landlock ABI is below the required floor",
            ));
        }
        let observation = reviewed_landlock_policy(abi)?;
        let attributes = LandlockRulesetAttr {
            handled_access_fs: observation.handled_filesystem,
            handled_access_net: observation.handled_network,
            scoped: observation.scoped,
        };
        // SAFETY: `attributes` has the ABI 6 three-u64 extensible layout and is alive for
        // the call. Older reviewed kernels accept its zero trailing field; ABI 10 treats
        // omitted quiet fields as zero. Flags are zero. Success returns a fresh descriptor.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attributes as *const LandlockRulesetAttr,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0u32,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful `landlock_create_ruleset` returned a fresh owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        Ok(Self {
            file: File::from(owned),
            observation,
        })
    }

    pub fn abi(&self) -> u32 {
        self.observation.abi
    }

    pub fn observation(&self) -> LandlockPolicyObservation {
        self.observation
    }

    pub fn allow_read_only(&self, path: &File) -> io::Result<()> {
        self.add_path(
            path,
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
        )
    }

    pub fn allow_read_write(&self, path: &File) -> io::Result<()> {
        self.add_path(
            path,
            self.observation.handled_filesystem & !LANDLOCK_ACCESS_FS_IOCTL_DEV,
        )
    }

    pub fn allow_read_write_file(&self, path: &File) -> io::Result<()> {
        self.add_path(
            path,
            LANDLOCK_ACCESS_FS_READ_FILE
                | LANDLOCK_ACCESS_FS_WRITE_FILE
                | LANDLOCK_ACCESS_FS_TRUNCATE,
        )
    }

    pub fn allow_device(&self, path: &File) -> io::Result<()> {
        self.add_path(
            path,
            LANDLOCK_ACCESS_FS_READ_FILE
                | LANDLOCK_ACCESS_FS_WRITE_FILE
                | (self.observation.handled_filesystem & LANDLOCK_ACCESS_FS_IOCTL_DEV),
        )
    }

    fn add_path(&self, path: &File, allowed_access: u64) -> io::Result<()> {
        if allowed_access & !self.observation.handled_filesystem != 0 {
            return Err(invalid(
                "Landlock rule grants an unhandled filesystem right",
            ));
        }
        let attributes = LandlockPathBeneathAttr {
            allowed_access,
            parent_fd: path.as_raw_fd(),
        };
        // SAFETY: both descriptors are live and owned by their Rust values; `attributes`
        // has the kernel path-beneath layout and is alive for the duration of the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.file.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &attributes as *const LandlockPathBeneathAttr,
                0u32,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn restrict_self(self) -> io::Result<u32> {
        set_no_new_privileges()?;
        // SAFETY: `self.file` owns a live completed ruleset descriptor and flags are zero;
        // success irreversibly confines the current thread and its future descendants.
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_restrict_self,
                self.file.as_raw_fd(),
                0u32,
            )
        };
        if result == 0 {
            Ok(self.observation.abi)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl SealedExecutable {
    pub fn descriptor(&self) -> i32 {
        self.file.as_raw_fd()
    }

    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub fn make_inheritable(&self) -> io::Result<i32> {
        clear_close_on_exec(self.file.as_raw_fd())
    }

    pub fn seals(&self) -> io::Result<i32> {
        // SAFETY: `self.file` owns a live descriptor and F_GET_SEALS takes no pointer argument.
        let result = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GET_SEALS) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    pub fn exec(self, arguments: &[&str], environment: &[(&str, &str)]) -> io::Error {
        let arguments = match arguments
            .iter()
            .map(|value| std::ffi::CString::new(*value))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(values) if !values.is_empty() => values,
            _ => return invalid("sealed executable arguments are empty or contain NUL"),
        };
        let environment = match environment
            .iter()
            .map(|(key, value)| std::ffi::CString::new(format!("{key}={value}")))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(values) => values,
            Err(_) => return invalid("sealed executable environment contains NUL"),
        };
        let mut argument_pointers = arguments
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        argument_pointers.push(std::ptr::null());
        let mut environment_pointers = environment
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        environment_pointers.push(std::ptr::null());
        let empty_path = c"";
        // SAFETY: the sealed descriptor, empty C path, and both NUL-terminated pointer arrays
        // remain alive for the call. AT_EMPTY_PATH executes exactly the owned sealed memfd.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                self.file.as_raw_fd(),
                empty_path.as_ptr(),
                argument_pointers.as_ptr(),
                environment_pointers.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        io::Error::last_os_error()
    }
}

impl SealedFile {
    pub fn descriptor(&self) -> i32 {
        self.file.as_raw_fd()
    }

    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub fn make_inheritable(&self) -> io::Result<i32> {
        clear_close_on_exec(self.file.as_raw_fd())
    }

    pub fn seals(&self) -> io::Result<i32> {
        // SAFETY: `self.file` owns a live descriptor and F_GET_SEALS takes no pointer argument.
        let result = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GET_SEALS) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn landlock_abi_version() -> io::Result<u32> {
    // SAFETY: the VERSION query requires a null attribute pointer and zero size; it returns
    // only an integer ABI version and creates no descriptor or caller-owned memory.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        u32::try_from(result).map_err(|_| invalid("Landlock ABI version exceeds u32"))
    }
}

pub fn set_no_new_privileges() -> io::Result<()> {
    // SAFETY: PR_SET_NO_NEW_PRIVS ignores arguments 3-5 when argument 2 is exactly one;
    // the operation is irreversible for the current thread and inherited by descendants.
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn no_new_privileges_active() -> io::Result<bool> {
    // SAFETY: PR_GET_NO_NEW_PRIVS reads no pointer and ignores arguments 2-5.
    let result = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ if result < 0 => Err(io::Error::last_os_error()),
        _ => Err(invalid("kernel returned a non-boolean no_new_privs value")),
    }
}

pub fn fill_random(bytes: &mut [u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(invalid("kernel random request is outside 1..4096 bytes"));
    }
    let mut filled = 0usize;
    while filled < bytes.len() {
        // SAFETY: the remaining mutable slice is valid writable storage for its reported length;
        // zero flags require the kernel CSPRNG and admit no userspace or weak fallback.
        let result = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(invalid("kernel random source returned zero bytes"));
        }
        filled = filled
            .checked_add(result as usize)
            .ok_or_else(|| invalid("kernel random byte count overflowed"))?;
    }
    Ok(())
}

pub fn zeroize(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: each pointer is derived from a distinct live mutable byte reference. Volatile
        // stores plus the compiler fence make secret erasure an observable operation.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

fn jump_equal(value: u32, jump_true: u8, jump_false: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: jump_true,
        jf: jump_false,
        k: value,
    }
}

fn jump_bits_set(value: u32, jump_true: u8, jump_false: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP_JSET_K,
        jt: jump_true,
        jf: jump_false,
        k: value,
    }
}

pub fn install_objective3_seccomp_filter() -> io::Result<()> {
    if !cfg!(target_arch = "x86_64") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Objective 3 seccomp architecture is not frozen",
        ));
    }
    let denied = [
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_open_tree,
        libc::SYS_mount_setattr,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_open_by_handle_at,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_adjtimex,
        libc::SYS_iopl,
        libc::SYS_ioperm,
        libc::SYS_vhangup,
        libc::SYS_fanotify_init,
    ];
    let namespace_clone_flags = (libc::CLONE_NEWNS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWTIME) as u32;
    let mut program = Vec::with_capacity(13 + denied.len() * 2);
    program.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET));
    program.push(jump_equal(AUDIT_ARCH_X86_64, 1, 0));
    program.push(statement(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS));
    program.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));
    program.push(jump_equal(libc::SYS_clone as u32, 0, 4));
    program.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_ZERO_OFFSET));
    program.push(jump_bits_set(namespace_clone_flags, 0, 1));
    program.push(statement(
        BPF_RET_K,
        libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
    ));
    program.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));
    program.push(jump_equal(libc::SYS_clone3 as u32, 0, 1));
    program.push(statement(
        BPF_RET_K,
        libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
    ));
    for syscall in denied {
        program.push(jump_equal(syscall as u32, 0, 1));
        program.push(statement(
            BPF_RET_K,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
    }
    program.push(statement(BPF_RET_K, libc::SECCOMP_RET_ALLOW));
    let descriptor_count =
        u16::try_from(program.len()).map_err(|_| invalid("seccomp program exceeds u16"))?;
    let filter = libc::sock_fprog {
        len: descriptor_count,
        filter: program.as_mut_ptr(),
    };
    set_no_new_privileges()?;
    // SAFETY: `filter` and its instruction vector remain alive and immutable for the call;
    // the verified classic-BPF program checks the architecture before every syscall rule.
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &filter as *const libc::sock_fprog,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn canonical_relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && path.is_ascii()
        && path.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains("//")
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

impl PinnedDirectory {
    pub fn open(root: &Path) -> io::Result<Self> {
        Self::open_with_policy(root, false, false)
    }

    pub fn open_mount_root(root: &Path) -> io::Result<Self> {
        Self::open_with_policy(root, true, false)
    }

    /// Opens a caller-independent kernel mount such as the fixed cgroup-v2 root. Unlike
    /// production data roots, its fixed absolute path may necessarily cross `/sys` first;
    /// callers must validate the returned filesystem type and mount identity.
    pub fn open_fixed_kernel_mount(root: &Path) -> io::Result<Self> {
        Self::open_with_policy(root, false, true)
    }

    fn open_with_policy(
        root: &Path,
        admit_final_mount: bool,
        allow_fixed_mount_crossings: bool,
    ) -> io::Result<Self> {
        let root_text = root
            .to_str()
            .ok_or_else(|| invalid("pinned root is not UTF-8"))?;
        if !root_text.starts_with('/') || root_text.ends_with('/') || root_text.contains("//") {
            return Err(invalid("pinned root is not a canonical absolute path"));
        }
        let relative = root_text
            .strip_prefix('/')
            .ok_or_else(|| invalid("pinned root is not absolute"))?;
        if !canonical_relative(relative) {
            return Err(invalid("pinned root components are not canonical"));
        }
        let filesystem_root = File::open("/")?;
        let (parent, leaf) = relative.rsplit_once('/').unwrap_or(("", relative));
        let (directory, path, resolution) = if allow_fixed_mount_crossings {
            (filesystem_root, relative, ROOT_RESOLUTION_FLAGS)
        } else if admit_final_mount {
            let parent_directory = if parent.is_empty() {
                filesystem_root
            } else {
                open_directory_at(&filesystem_root, parent, RESOLUTION_FLAGS)?
            };
            (parent_directory, leaf, ROOT_RESOLUTION_FLAGS)
        } else {
            (filesystem_root, relative, RESOLUTION_FLAGS)
        };
        let path = std::ffi::CString::new(path).map_err(|_| invalid("pinned root contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: resolution,
        };
        // SAFETY: `path` and `how` are initialized and alive; the root FD is owned and live;
        // the resolution policy rejects traversal, symlinks, magic links, and mount crossing.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                directory.as_raw_fd(),
                path.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat2 returns a new descriptor owned by the caller exactly once.
        let directory = File::from(unsafe { OwnedFd::from_raw_fd(raw as i32) });
        let metadata = directory.metadata()?;
        if !metadata.is_dir() {
            return Err(invalid("pinned root is not a directory"));
        }
        Ok(Self {
            directory,
            identity: FileIdentity::capture(&metadata),
        })
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub fn filesystem_identity(&self) -> io::Result<FilesystemIdentity> {
        let mut status = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: `status` points to writable storage for one `statfs`, and the pinned
        // directory descriptor remains live for the complete call.
        if unsafe { libc::fstatfs(self.directory.as_raw_fd(), status.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful `fstatfs` call initialized the complete structure.
        let status = unsafe { status.assume_init() };
        let mut volume = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
        // SAFETY: `volume` points to writable storage for one `statvfs`, and the pinned
        // directory descriptor remains live for the complete call.
        if unsafe { libc::fstatvfs(self.directory.as_raw_fd(), volume.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful `fstatvfs` call initialized the complete structure.
        let volume = unsafe { volume.assume_init() };
        let mut extended = std::mem::MaybeUninit::<Statx>::zeroed();
        // SAFETY: the empty path is a valid NUL-terminated C string, `AT_EMPTY_PATH`
        // targets the live directory descriptor, and `extended` is writable output.
        if unsafe {
            libc::syscall(
                libc::SYS_statx,
                self.directory.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH,
                STATX_MNT_ID_UNIQUE,
                extended.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful `statx` call initialized the complete structure.
        let extended = unsafe { extended.assume_init() };
        if extended.mask & STATX_MNT_ID_UNIQUE == 0 || extended.mount_id == 0 {
            return Err(invalid("kernel did not report a unique mount identity"));
        }
        Ok(FilesystemIdentity {
            mount_id: extended.mount_id,
            filesystem_type: status.f_type as u64,
            read_only: volume.f_flag & libc::ST_RDONLY != 0,
        })
    }

    pub fn make_inheritable(&self) -> io::Result<i32> {
        clear_close_on_exec(self.directory.as_raw_fd())
    }

    pub fn create_private_directory(&self, name: &str) -> io::Result<Self> {
        if name.contains('/') || !canonical_relative(name) {
            return Err(invalid(
                "private directory name is not one closed component",
            ));
        }
        let name = std::ffi::CString::new(name)
            .map_err(|_| invalid("private directory name contains NUL"))?;
        // SAFETY: the pinned parent descriptor and NUL-terminated single-component name remain
        // live for mkdirat; mode 0700 grants no group/other pathname mutation authority.
        if unsafe { libc::mkdirat(self.directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let directory = open_directory_at(
            &self.directory,
            name.to_str()
                .map_err(|_| invalid("private directory name is not UTF-8"))?,
            RESOLUTION_FLAGS,
        )?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(invalid("private directory identity or mode changed"));
        }
        Ok(Self {
            directory,
            identity: FileIdentity::capture(&metadata),
        })
    }

    pub fn open_child_directory(&self, name: &str) -> io::Result<Self> {
        if name.contains('/') || !canonical_relative(name) {
            return Err(invalid("child directory name is not one closed component"));
        }
        let directory = open_directory_at(&self.directory, name, RESOLUTION_FLAGS)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() {
            return Err(invalid("child directory is not a directory"));
        }
        Ok(Self {
            directory,
            identity: FileIdentity::capture(&metadata),
        })
    }

    /// One bounded local inventory from a retained directory descriptor. d_type
    /// and d_ino are hints only: every entry is identified through confined O_PATH.
    /// A caller captures descendants, then compares a second inventory and its
    /// final expected content commitment; this alone is not an atomic tree snapshot.
    pub fn inventory(
        &self,
        maximum_entries: usize,
        maximum_name_bytes: usize,
    ) -> io::Result<Vec<DirectoryEntryIdentity>> {
        let before = FileIdentity::capture(&self.directory.metadata()?);
        if before != self.identity {
            return Err(capture_error(CaptureIoFailure::Race));
        }
        let duplicate = self.directory.try_clone()?;
        // SAFETY: duplicate owns a live directory descriptor. Ownership transfers
        // to libc only on success; an error leaves Rust responsible for closing it.
        let pointer = unsafe { libc::fdopendir(duplicate.as_raw_fd()) };
        if pointer.is_null() {
            return Err(io::Error::last_os_error());
        }
        let _transferred = duplicate.into_raw_fd();
        let stream = DirectoryStream(pointer);
        // SAFETY: stream is live. dup shares the directory offset; explicitly
        // rewind so repeated inventories cannot report an already consumed EOF.
        unsafe {
            libc::rewinddir(stream.0);
        }
        let mut entries = Vec::new();
        let mut name_bytes = 0usize;
        loop {
            // SAFETY: errno is thread-local, stream is live, and readdir's result
            // is used/copied before the next call can invalidate its storage.
            let entry = unsafe {
                *libc::__errno_location() = 0;
                let entry = libc::readdir(stream.0);
                if entry.is_null() && *libc::__errno_location() != 0 {
                    return Err(io::Error::last_os_error());
                }
                entry
            };
            if entry.is_null() {
                break;
            }
            // SAFETY: non-null readdir result remains valid until the next call.
            let name = unsafe { &(*entry).d_name };
            let length = name
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(|| capture_error(CaptureIoFailure::Path))?;
            if (length == 1 && name[0] == b'.' as libc::c_char)
                || (length == 2
                    && name[0] == b'.' as libc::c_char
                    && name[1] == b'.' as libc::c_char)
            {
                continue;
            }
            if entries.len() >= maximum_entries {
                return Err(capture_error(CaptureIoFailure::Limit));
            }
            name_bytes = name_bytes
                .checked_add(length)
                .filter(|n| *n <= maximum_name_bytes)
                .ok_or_else(|| capture_error(CaptureIoFailure::Limit))?;
            // No lossy decoding: non-ASCII bytes and noncanonical names refuse.
            let bytes: Vec<u8> = name[..length].iter().map(|byte| *byte as u8).collect();
            let name =
                String::from_utf8(bytes).map_err(|_| capture_error(CaptureIoFailure::Path))?;
            if name.contains('/') || !canonical_relative(&name) {
                return Err(capture_error(CaptureIoFailure::Path));
            }
            let held = pin_entry_at(&self.directory, &name)?;
            let identity = FileIdentity::capture(&held.metadata()?);
            entries
                .try_reserve(1)
                .map_err(|_| capture_error(CaptureIoFailure::Limit))?;
            entries.push(DirectoryEntryIdentity { name, identity });
        }
        entries.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        if entries.windows(2).any(|pair| pair[0].name == pair[1].name)
            || FileIdentity::capture(&self.directory.metadata()?) != before
        {
            return Err(capture_error(CaptureIoFailure::Race));
        }
        Ok(entries)
    }

    pub fn stage_private_file(
        &self,
        name: &str,
        bytes: &[u8],
        maximum_bytes: u64,
        final_mode: u32,
    ) -> io::Result<CapturedRegularFile> {
        if name.contains('/')
            || !canonical_relative(name)
            || bytes.len() as u64 > maximum_bytes
            || !matches!(final_mode, 0o400 | 0o500 | 0o600)
        {
            return Err(invalid("private staged file parameters are not admitted"));
        }
        let name = std::ffi::CString::new(name)
            .map_err(|_| invalid("private staged file name contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_CREAT
                | libc::O_EXCL
                | libc::O_RDWR
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW) as u64,
            mode: 0o600,
            resolve: RESOLUTION_FLAGS,
        };
        // SAFETY: name/how are initialized and alive, the parent descriptor is pinned, and
        // O_EXCL plus the resolution mask creates exactly one new non-symlink private inode.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.directory.as_raw_fd(),
                name.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat2 returned a fresh descriptor owned exactly once here.
        let mut file = File::from(unsafe { OwnedFd::from_raw_fd(raw as i32) });
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        file.set_permissions(std::fs::Permissions::from_mode(final_mode))?;
        file.seek(SeekFrom::Start(0))?;
        let mut recaptured = Vec::with_capacity(bytes.len());
        (&file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut recaptured)?;
        let metadata = file.metadata()?;
        if recaptured != bytes
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o777 != final_mode
            || metadata.size() != bytes.len() as u64
        {
            return Err(invalid("private staged file recapture or identity differs"));
        }
        Ok(CapturedRegularFile {
            file,
            bytes: recaptured,
            identity: FileIdentity::capture(&metadata),
        })
    }

    pub fn write_control(&self, name: &str, value: &[u8]) -> io::Result<()> {
        if name.contains('/') || !canonical_relative(name) || value.is_empty() || value.len() > 4096
        {
            return Err(invalid("control write parameters are not admitted"));
        }
        let name =
            std::ffi::CString::new(name).map_err(|_| invalid("control file name contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLUTION_FLAGS,
        };
        // SAFETY: name/how are initialized and alive, and resolution is beneath the pinned
        // descriptor without symlinks or mount crossings; success returns one fresh write FD.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.directory.as_raw_fd(),
                name.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat2 returned a fresh descriptor owned exactly once here.
        let mut file = File::from(unsafe { OwnedFd::from_raw_fd(raw as i32) });
        file.write_all(value)?;
        file.flush()
    }

    pub fn read_control(&self, name: &str, maximum_bytes: u64) -> io::Result<String> {
        if name.contains('/') || !canonical_relative(name) || maximum_bytes == 0 {
            return Err(invalid("control read parameters are not admitted"));
        }
        let name =
            std::ffi::CString::new(name).map_err(|_| invalid("control file name contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: RESOLUTION_FLAGS,
        };
        // SAFETY: name/how are initialized and alive, and resolution is beneath the pinned
        // descriptor without symlinks or mount crossings; success returns one fresh read FD.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.directory.as_raw_fd(),
                name.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat2 returned a fresh descriptor owned exactly once here.
        let file = File::from(unsafe { OwnedFd::from_raw_fd(raw as i32) });
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.gid() != 0 {
            return Err(invalid(
                "control file identity is not root-owned regular data",
            ));
        }
        let mut bytes = Vec::new();
        (&file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(invalid("control file exceeds its read bound"));
        }
        String::from_utf8(bytes).map_err(|_| invalid("control file is not UTF-8"))
    }

    pub fn remove_private_directory(&self, name: &str, expected: &FileIdentity) -> io::Result<()> {
        if name.contains('/') || !canonical_relative(name) {
            return Err(invalid(
                "private directory removal name is not one component",
            ));
        }
        let observed = open_directory_at(&self.directory, name, RESOLUTION_FLAGS)?;
        let identity = FileIdentity::capture(&observed.metadata()?);
        if &identity != expected {
            return Err(invalid("private directory removal identity changed"));
        }
        drop(observed);
        let name = std::ffi::CString::new(name)
            .map_err(|_| invalid("private directory removal name contains NUL"))?;
        // SAFETY: the parent descriptor and NUL-terminated closed component remain live; the
        // identity was rechecked and AT_REMOVEDIR cannot remove a file or nonempty directory.
        if unsafe {
            libc::unlinkat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn capture_regular_file(
        &self,
        relative: &str,
        maximum_bytes: u64,
    ) -> io::Result<CapturedRegularFile> {
        let PinnedRegularFile { mut file, identity } =
            self.open_regular_file(relative, maximum_bytes)?;
        let capacity =
            usize::try_from(identity.size).map_err(|_| capture_error(CaptureIoFailure::Limit))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| capture_error(CaptureIoFailure::Limit))?;
        bytes.resize(capacity, 0);
        file.read_exact(&mut bytes).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                capture_error(CaptureIoFailure::Race)
            } else {
                error
            }
        })?;
        // Probe growth without appending to, or enlarging, the admitted buffer.
        if file.read(&mut [0u8; 1])? != 0 || FileIdentity::capture(&file.metadata()?) != identity {
            return Err(capture_error(CaptureIoFailure::Race));
        }
        Ok(CapturedRegularFile {
            file,
            bytes,
            identity,
        })
    }

    pub fn open_regular_file(
        &self,
        relative: &str,
        maximum_bytes: u64,
    ) -> io::Result<PinnedRegularFile> {
        let file = pin_entry_at(&self.directory, relative)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(capture_error(CaptureIoFailure::Type));
        }
        if metadata.size() > maximum_bytes {
            return Err(capture_error(CaptureIoFailure::Limit));
        }
        let identity = FileIdentity::capture(&metadata);
        upgrade_regular_inode(file, identity)
    }

    pub fn stage_private_copy(
        &self,
        name: &str,
        source: &PinnedRegularFile,
        maximum_bytes: u64,
        final_mode: u32,
    ) -> io::Result<PinnedRegularFile> {
        if name.contains('/')
            || !canonical_relative(name)
            || source.identity.size > maximum_bytes
            || !matches!(final_mode, 0o400 | 0o500 | 0o600)
        {
            return Err(invalid("private streamed-copy parameters are not admitted"));
        }
        let name = std::ffi::CString::new(name)
            .map_err(|_| invalid("private streamed-copy name contains NUL"))?;
        let how = OpenHow {
            flags: (libc::O_CREAT
                | libc::O_EXCL
                | libc::O_RDWR
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW) as u64,
            mode: 0o600,
            resolve: RESOLUTION_FLAGS,
        };
        // SAFETY: name/how are initialized and alive, the destination parent is pinned, and
        // O_EXCL plus the resolution policy creates exactly one fresh private regular inode.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.directory.as_raw_fd(),
                name.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat2 returned a fresh descriptor owned exactly once here.
        let mut destination = File::from(unsafe { OwnedFd::from_raw_fd(raw as i32) });
        let mut source_reader = source.file.try_clone()?;
        source_reader.seek(SeekFrom::Start(0))?;
        let copied = io::copy(
            &mut source_reader.take(maximum_bytes.saturating_add(1)),
            &mut destination,
        )?;
        if copied != source.identity.size || copied > maximum_bytes {
            return Err(invalid("private streamed copy length differs"));
        }
        destination.flush()?;
        destination.sync_all()?;
        destination.set_permissions(std::fs::Permissions::from_mode(final_mode))?;
        let mut source_compare = source.file.try_clone()?;
        let mut destination_compare = destination.try_clone()?;
        source_compare.seek(SeekFrom::Start(0))?;
        destination_compare.seek(SeekFrom::Start(0))?;
        let mut source_chunk = [0u8; 64 * 1024];
        let mut destination_chunk = [0u8; 64 * 1024];
        loop {
            let source_read = source_compare.read(&mut source_chunk)?;
            let destination_read = destination_compare.read(&mut destination_chunk)?;
            if source_read != destination_read
                || source_chunk[..source_read] != destination_chunk[..destination_read]
            {
                return Err(invalid("private streamed copy byte comparison differs"));
            }
            if source_read == 0 {
                break;
            }
        }
        let source_after = FileIdentity::capture(&source.file.metadata()?);
        let destination_identity = FileIdentity::capture(&destination.metadata()?);
        if source_after != source.identity
            || destination_identity.size != source.identity.size
            || destination_identity.links != 1
            || destination_identity.uid != 0
            || destination_identity.gid != 0
            || destination_identity.mode & 0o777 != final_mode
        {
            return Err(invalid("streamed source or destination identity changed"));
        }
        Ok(PinnedRegularFile {
            file: destination,
            identity: destination_identity,
        })
    }
}

/// O_PATH does not open a device or wait on a FIFO. Every caller-supplied path
/// keeps the full no-link/no-mount-crossing resolution profile.
fn pin_entry_at(root: &File, relative: &str) -> io::Result<File> {
    if !canonical_relative(relative) {
        return Err(capture_error(CaptureIoFailure::Path));
    }
    let path =
        std::ffi::CString::new(relative).map_err(|_| capture_error(CaptureIoFailure::Path))?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLUTION_FLAGS,
    };
    // SAFETY: root/path/how remain live; successful openat2 returns a new owned FD.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful syscall transferred exactly one fresh descriptor.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(raw as i32) }))
}

/// Upgrades only our held inode through our own verified procfs FD directory.
/// The source pathname is deliberately unavailable here. resolve=0 is confined
/// to this internally generated magic-link lookup, never a source-root fallback.
fn upgrade_regular_inode(pinned: File, identity: FileIdentity) -> io::Result<PinnedRegularFile> {
    let proc = PinnedDirectory::open_fixed_kernel_mount(Path::new("/proc"))
        .map_err(|_| capture_error(CaptureIoFailure::Unsupported))?;
    if proc
        .filesystem_identity()
        .map_err(|_| capture_error(CaptureIoFailure::Unsupported))?
        .filesystem_type
        != libc::PROC_SUPER_MAGIC as u64
    {
        return Err(capture_error(CaptureIoFailure::Unsupported));
    }
    let fd_directory = open_directory_at(
        &proc.directory,
        &format!("{}/fd", std::process::id()),
        RESOLUTION_FLAGS,
    )
    .map_err(|_| capture_error(CaptureIoFailure::Unsupported))?;
    let metadata = fd_directory.metadata()?;
    // SAFETY: geteuid has no arguments or borrowed memory and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if metadata.dev() != proc.identity.device || metadata.uid() != uid || !metadata.is_dir() {
        return Err(capture_error(CaptureIoFailure::Unsupported));
    }
    let descriptor = std::ffi::CString::new(pinned.as_raw_fd().to_string())
        .map_err(|_| capture_error(CaptureIoFailure::Unsupported))?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY) as u64,
        mode: 0,
        resolve: 0,
    };
    // SAFETY: the original O_PATH FD, procfs directory and numeric string remain
    // live. No caller controls this path or FD number. Returned FD is owned once.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            fd_directory.as_raw_fd(),
            descriptor.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if raw < 0 {
        return Err(capture_error(CaptureIoFailure::Unsupported));
    }
    // SAFETY: successful syscall returned one fresh descriptor.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(raw as i32) });
    if FileIdentity::capture(&file.metadata()?) != identity
        || FileIdentity::capture(&pinned.metadata()?) != identity
    {
        return Err(capture_error(CaptureIoFailure::Race));
    }
    Ok(PinnedRegularFile { file, identity })
}

fn open_directory_at(root: &File, relative: &str, resolution: u64) -> io::Result<File> {
    if !canonical_relative(relative) {
        return Err(invalid("directory path is not canonical"));
    }
    let path =
        std::ffi::CString::new(relative).map_err(|_| invalid("directory path contains NUL"))?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: resolution,
    };
    // SAFETY: `path` and `how` are initialized and alive; `root` owns a live directory
    // descriptor; a successful return is a fresh descriptor owned exactly once below.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `openat2` returned a fresh descriptor owned by this function.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(raw as i32) }))
}

fn clear_close_on_exec(descriptor: i32) -> io::Result<i32> {
    // SAFETY: `descriptor` is borrowed from a live owned File and F_GETFD has no pointer argument.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor remains live; F_SETFD consumes only the integer flag value.
    let result = unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if result == 0 {
        Ok(descriptor)
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn seal_executable_bytes(
    name: &str,
    bytes: &[u8],
    maximum_bytes: u64,
) -> io::Result<SealedExecutable> {
    if name.is_empty()
        || name.len() > 249
        || !name.is_ascii()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || bytes.len() as u64 > maximum_bytes
    {
        return Err(invalid("memfd name or byte length is not admitted"));
    }
    let name = std::ffi::CString::new(name).map_err(|_| invalid("memfd name contains NUL"))?;
    // SAFETY: `name` is NUL-terminated and alive for the call; flags are the frozen Linux UAPI bits.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | MFD_EXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `memfd_create` returned a fresh descriptor owned by this function.
    let owned = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let mut file = File::from(owned);
    file.write_all(bytes)?;
    file.flush()?;
    file.seek(SeekFrom::Start(0))?;
    let mut recaptured = Vec::with_capacity(bytes.len());
    (&file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut recaptured)?;
    if recaptured != bytes {
        return Err(invalid("memfd independent byte recapture disagreed"));
    }
    file.seek(SeekFrom::Start(0))?;
    // SAFETY: `file` owns a live memfd created with MFD_ALLOW_SEALING; the third argument is
    // the frozen bitmask and contains no pointer. Success makes the byte extent immutable.
    let added = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, REQUIRED_MEMFD_SEALS) };
    if added != 0 {
        return Err(io::Error::last_os_error());
    }
    let result = SealedExecutable {
        file,
        byte_length: bytes.len() as u64,
    };
    if result.seals()? != REQUIRED_MEMFD_SEALS {
        return Err(invalid("memfd required seals did not read back exactly"));
    }
    Ok(result)
}

pub fn seal_file_bytes(
    name: &str,
    bytes: &[u8],
    maximum_bytes: u64,
    mode: u32,
) -> io::Result<SealedFile> {
    seal_file_bytes_with_policy(name, bytes, maximum_bytes, mode, false)
}

pub fn seal_data_file_bytes(
    name: &str,
    bytes: &[u8],
    maximum_bytes: u64,
    mode: u32,
) -> io::Result<SealedFile> {
    if mode != 0o400 {
        return Err(invalid("sealed data file must be non-executable"));
    }
    seal_file_bytes_with_policy(name, bytes, maximum_bytes, mode, true)
}

fn seal_file_bytes_with_policy(
    name: &str,
    bytes: &[u8],
    maximum_bytes: u64,
    mode: u32,
    no_execute: bool,
) -> io::Result<SealedFile> {
    if name.is_empty()
        || name.len() > 249
        || !name.is_ascii()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || bytes.len() as u64 > maximum_bytes
        || !matches!(mode, 0o400 | 0o500)
    {
        return Err(invalid("sealed-file name, length, or mode is not admitted"));
    }
    let name = std::ffi::CString::new(name).map_err(|_| invalid("memfd name contains NUL"))?;
    // SAFETY: `name` is NUL-terminated and alive; flags request a private sealable data memfd.
    let memfd_flags =
        libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | if no_execute { MFD_NOEXEC_SEAL } else { 0 };
    let raw = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), memfd_flags) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `memfd_create` returned a fresh descriptor owned exactly once here.
    let owned = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let mut file = File::from(owned);
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    file.write_all(bytes)?;
    file.flush()?;
    file.seek(SeekFrom::Start(0))?;
    let mut recaptured = Vec::with_capacity(bytes.len());
    (&file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut recaptured)?;
    if recaptured != bytes {
        return Err(invalid("sealed-file independent byte recapture disagreed"));
    }
    file.seek(SeekFrom::Start(0))?;
    // SAFETY: `file` is a live MFD_ALLOW_SEALING memfd and the fixed mask has no pointer.
    let added = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, REQUIRED_MEMFD_SEALS) };
    if added != 0 {
        return Err(io::Error::last_os_error());
    }
    let result = SealedFile {
        file,
        byte_length: bytes.len() as u64,
    };
    let required_seals = if no_execute {
        REQUIRED_DATA_MEMFD_SEALS
    } else {
        REQUIRED_MEMFD_SEALS
    };
    if result.seals()? != required_seals {
        return Err(invalid(
            "sealed-file required seals did not read back exactly",
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{create_dir, write};
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("keep-linux-abi-{}-{nonce}", std::process::id()));
        create_dir(&path).unwrap();
        path
    }

    #[test]
    fn capture_refuses_fifo_socket_directory_and_hardlink_without_io() {
        let root = scratch();
        let fifo = std::ffi::CString::new(root.join("fifo").to_str().unwrap()).unwrap();
        // SAFETY: fresh owned test path, valid C string, no device creation/mount.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let socket = std::os::unix::net::UnixListener::bind(root.join("socket")).unwrap();
        create_dir(root.join("directory")).unwrap();
        write(root.join("linked"), b"data").unwrap();
        std::fs::hard_link(root.join("linked"), root.join("alias")).unwrap();
        let pinned = PinnedDirectory::open(&root).unwrap();
        let start = std::time::Instant::now();
        for name in ["fifo", "socket", "directory", "linked", "alias"] {
            for error in [
                pinned.capture_regular_file(name, 64).unwrap_err(),
                pinned.open_regular_file(name, 64).unwrap_err(),
            ] {
                assert_eq!(
                    error
                        .get_ref()
                        .and_then(|error| error.downcast_ref::<CaptureIoFailure>()),
                    Some(&CaptureIoFailure::Type)
                );
            }
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        drop(socket);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capture_empty_and_exact_size_keep_owned_bytes_after_path_replacement() {
        let root = scratch();
        write(root.join("empty"), b"").unwrap();
        write(root.join("input"), b"original").unwrap();
        let pinned = PinnedDirectory::open(&root).unwrap();
        assert!(
            pinned
                .capture_regular_file("empty", 0)
                .unwrap()
                .bytes()
                .is_empty()
        );
        let captured = pinned.capture_regular_file("input", 8).unwrap();
        std::fs::rename(root.join("input"), root.join("old")).unwrap();
        write(root.join("input"), b"attacker").unwrap();
        assert_eq!(captured.into_bytes(), b"original");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn descriptor_upgrade_never_reopens_the_replaced_source_path() {
        let root = scratch();
        write(root.join("input"), b"original").unwrap();
        let directory = PinnedDirectory::open(&root).unwrap();
        let held = pin_entry_at(&directory.directory, "input").unwrap();
        let identity = FileIdentity::capture(&held.metadata().unwrap());
        std::fs::rename(root.join("input"), root.join("old")).unwrap();
        write(root.join("input"), b"attacker").unwrap();
        match upgrade_regular_inode(held, identity) {
            Ok(mut opened) => {
                let mut bytes = Vec::new();
                opened.file.read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, b"original");
            }
            Err(error) => assert_eq!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<CaptureIoFailure>()),
                Some(&CaptureIoFailure::Race)
            ),
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inventories_are_sorted_bounded_repeatable_and_keep_the_original_fd() {
        let root = scratch();
        write(root.join("z"), b"z").unwrap();
        write(root.join("a"), b"aa").unwrap();
        create_dir(root.join("child")).unwrap();
        let directory = PinnedDirectory::open(&root).unwrap();
        let first = directory.inventory(3, 7).unwrap();
        assert_eq!(
            first
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["a", "child", "z"]
        );
        assert_eq!(first[0].identity.size, 2);
        assert_eq!(
            directory.inventory(3, 7).unwrap(),
            first,
            "fdopendir must not consume original FD or leave EOF for the next inventory"
        );
        for error in [
            directory.inventory(2, 7).unwrap_err(),
            directory.inventory(3, 6).unwrap_err(),
        ] {
            assert_eq!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<CaptureIoFailure>()),
                Some(&CaptureIoFailure::Limit)
            );
        }
        assert_eq!(
            directory.capture_regular_file("z", 1).unwrap().bytes(),
            b"z"
        );
        write(root.join("added"), b"changed").unwrap();
        // Same-clock-tick mutations need not change directory metadata. The
        // consumer must compare complete inventories, never only timestamps.
        match directory.inventory(4, 64) {
            Ok(after) => assert_ne!(after, first),
            Err(error) => assert_eq!(
                CaptureIoFailure::from_io(&error),
                Some(CaptureIoFailure::Race)
            ),
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn captures_one_regular_leaf_from_the_pinned_root() {
        let root = scratch();
        write(root.join("input"), b"bound bytes\n").unwrap();
        let pinned = PinnedDirectory::open(&root).unwrap();
        let capture = pinned.capture_regular_file("input", 64).unwrap();
        assert_eq!(capture.bytes(), b"bound bytes\n");
        assert_eq!(capture.identity().size, 12);
        assert!(capture.descriptor() >= 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn captures_kernel_mount_and_filesystem_identity() {
        let root = scratch();
        let pinned = PinnedDirectory::open(&root).unwrap();
        let identity = pinned.filesystem_identity().unwrap();
        assert_ne!(identity.mount_id, 0);
        assert_ne!(identity.filesystem_type, 0);
        assert!(!identity.read_only);
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn refuses_traversal_links_and_oversize() {
        let root = scratch();
        write(root.join("small"), b"1234").unwrap();
        symlink("small", root.join("alias")).unwrap();
        let pinned = PinnedDirectory::open(&root).unwrap();
        for path in ["", ".", "..", "../small", "/small", "a//b", "small/"] {
            assert!(
                pinned.capture_regular_file(path, 64).is_err(),
                "accepted {path:?}"
            );
        }
        assert!(pinned.capture_regular_file("alias", 64).is_err());
        assert!(pinned.capture_regular_file("small", 3).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_a_symlink_anywhere_in_the_pinned_root_path() {
        let parent = scratch();
        let real = parent.join("real");
        create_dir(&real).unwrap();
        let alias = parent.join("alias");
        symlink(&real, &alias).unwrap();
        assert!(PinnedDirectory::open(&alias).is_err());
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn pinned_root_identity_survives_pathname_replacement() {
        let parent = scratch();
        let live = parent.join("live");
        create_dir(&live).unwrap();
        write(live.join("input"), b"authenticated").unwrap();
        let pinned = PinnedDirectory::open(&live).unwrap();
        let displaced = parent.join("displaced");
        std::fs::rename(&live, &displaced).unwrap();
        create_dir(&live).unwrap();
        write(live.join("input"), b"substitute").unwrap();
        let capture = pinned.capture_regular_file("input", 64).unwrap();
        assert_eq!(capture.bytes(), b"authenticated");
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn executable_memfd_recaptures_and_seals_exact_bytes() {
        let mut sealed = seal_executable_bytes("keep-test", b"executable bytes", 64).unwrap();
        assert_eq!(sealed.byte_length(), 16);
        assert_eq!(sealed.seals().unwrap(), REQUIRED_MEMFD_SEALS);
        assert!(sealed.file.write_all(b"mutation").is_err());
        assert!(sealed.file.set_len(0).is_err());
    }

    #[test]
    fn data_memfd_is_non_executable_read_only_and_exactly_sealed() {
        let mut sealed =
            seal_data_file_bytes("keep-data-test", b"snapshot bytes", 64, 0o400).unwrap();
        assert_eq!(sealed.byte_length(), 14);
        assert_eq!(sealed.seals().unwrap(), REQUIRED_DATA_MEMFD_SEALS);
        assert_eq!(
            sealed.file.metadata().unwrap().permissions().mode() & 0o777,
            0o400
        );
        let execution =
            std::process::Command::new(format!("/proc/self/fd/{}", sealed.descriptor()))
                .status()
                .unwrap_err();
        assert_eq!(execution.raw_os_error(), Some(libc::EACCES));
        assert!(sealed.file.write_all(b"mutation").is_err());
    }

    #[test]
    fn host_exposes_landlock_and_no_new_privileges_is_one_way() {
        assert!(landlock_abi_version().unwrap() >= 3);
        let _initial_state = no_new_privileges_active().unwrap();
        set_no_new_privileges().unwrap();
        assert!(no_new_privileges_active().unwrap());
    }

    #[test]
    fn landlock_rights_are_exact_through_abi_ten_and_unknown_abis_refuse() {
        let abi3 = reviewed_landlock_policy(3).unwrap();
        assert_eq!(abi3.abi, 3);
        assert_eq!(abi3.handled_network, 0);
        assert_eq!(abi3.scoped, 0);
        assert_eq!(abi3.handled_filesystem & LANDLOCK_ACCESS_FS_IOCTL_DEV, 0);
        assert_ne!(abi3.handled_filesystem & LANDLOCK_ACCESS_FS_REFER, 0);
        assert_ne!(abi3.handled_filesystem & LANDLOCK_ACCESS_FS_TRUNCATE, 0);

        let abi4 = reviewed_landlock_policy(4).unwrap();
        assert_eq!(
            abi4.handled_network,
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
        );
        assert_eq!(abi4.scoped, 0);

        let abi5 = reviewed_landlock_policy(5).unwrap();
        assert_ne!(abi5.handled_filesystem & LANDLOCK_ACCESS_FS_IOCTL_DEV, 0);
        assert_eq!(abi5.scoped, 0);

        let abi6 = reviewed_landlock_policy(6).unwrap();
        assert_eq!(
            abi6.scoped,
            LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL
        );
        assert_eq!(abi6.handled_filesystem & LANDLOCK_ACCESS_FS_RESOLVE_UNIX, 0);

        let abi9 = reviewed_landlock_policy(9).unwrap();
        assert_ne!(abi9.handled_filesystem & LANDLOCK_ACCESS_FS_RESOLVE_UNIX, 0);
        assert_eq!(
            abi9.handled_network,
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
        );

        let abi10 = reviewed_landlock_policy(10).unwrap();
        assert_eq!(
            abi10.handled_network,
            LANDLOCK_ACCESS_NET_BIND_TCP
                | LANDLOCK_ACCESS_NET_CONNECT_TCP
                | LANDLOCK_ACCESS_NET_BIND_UDP
                | LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP
        );
        assert!(reviewed_landlock_policy(2).is_err());
        assert!(reviewed_landlock_policy(11).is_err());
    }

    #[test]
    fn pidfd_binds_and_signals_the_exact_child_incarnation() {
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = ProcessIdentity::open(child.id()).unwrap();
        assert_eq!(identity.pid(), child.id());
        assert!(!identity.has_exited().unwrap());
        assert_eq!(
            identity.send_signal(libc::SIGUSR1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        identity.terminate().unwrap();
        child.wait().unwrap();
        assert!(identity.has_exited().unwrap());
    }

    #[test]
    fn private_staging_is_exclusive_descriptor_relative_and_exact() {
        let root = scratch();
        let pinned = PinnedDirectory::open(&root).unwrap();
        let attempt = pinned
            .create_private_directory("keep-attempt-0123")
            .unwrap();
        assert!(
            pinned
                .create_private_directory("keep-attempt-0123")
                .is_err()
        );
        let staged = attempt
            .stage_private_file("firecracker", b"captured vmm bytes", 64, 0o500)
            .unwrap();
        assert_eq!(staged.bytes(), b"captured vmm bytes");
        assert_eq!(staged.identity().mode & 0o777, 0o500);
        assert_eq!(staged.identity().links, 1);
        assert!(
            attempt
                .stage_private_file("firecracker", b"substitute", 64, 0o500)
                .is_err()
        );
        for invalid in ["", ".", "../escape", "nested/file", "/absolute"] {
            assert!(
                attempt
                    .stage_private_file(invalid, b"bytes", 64, 0o500)
                    .is_err(),
                "accepted {invalid:?}"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
        assert_eq!(staged.bytes(), b"captured vmm bytes");
    }

    #[test]
    fn control_io_and_identity_bound_directory_removal_are_descriptor_relative() {
        let root = scratch();
        write(root.join("control"), b"").unwrap();
        let pinned = PinnedDirectory::open(&root).unwrap();
        pinned.write_control("control", b"exact\n").unwrap();
        assert_eq!(pinned.read_control("control", 64).unwrap(), "exact\n");
        for invalid in ["", "../control", "/control", "nested/control"] {
            assert!(pinned.read_control(invalid, 64).is_err());
            assert!(pinned.write_control(invalid, b"x").is_err());
        }
        let private = pinned.create_private_directory("remove-me").unwrap();
        let wrong = FileIdentity {
            inode: private.identity().inode.wrapping_add(1),
            ..private.identity().clone()
        };
        assert!(
            pinned
                .remove_private_directory("remove-me", &wrong)
                .is_err()
        );
        pinned
            .remove_private_directory("remove-me", private.identity())
            .unwrap();
        assert!(!root.join("remove-me").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn kernel_random_has_no_fallback_and_fills_exact_requests() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        fill_random(&mut first).unwrap();
        fill_random(&mut second).unwrap();
        assert_ne!(first, [0u8; 32]);
        assert_ne!(first, second);
        assert!(fill_random(&mut []).is_err());
        assert!(fill_random(&mut [0u8; 4097]).is_err());
        zeroize(&mut first);
        assert_eq!(first, [0u8; 32]);
    }

    #[test]
    fn large_file_staging_streams_the_pinned_inode_and_compares_exact_bytes() {
        let source_root = scratch();
        let destination_root = scratch();
        let expected = (0..=(2 * 1024 * 1024))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        write(source_root.join("rootfs.ext4"), &expected).unwrap();
        let source_directory = PinnedDirectory::open(&source_root).unwrap();
        let source = source_directory
            .open_regular_file("rootfs.ext4", 3 * 1024 * 1024)
            .unwrap();
        let mut streamed = Vec::new();
        assert_eq!(
            source
                .read_bounded_chunks(3 * 1024 * 1024, |chunk| {
                    streamed.extend_from_slice(chunk);
                    Ok(())
                })
                .unwrap(),
            expected.len() as u64
        );
        assert_eq!(streamed, expected);
        let displaced_source_root = source_root.with_extension("displaced");
        std::fs::rename(&source_root, &displaced_source_root).unwrap();
        create_dir(&source_root).unwrap();
        write(source_root.join("rootfs.ext4"), b"substitute").unwrap();
        let destination = PinnedDirectory::open(&destination_root).unwrap();
        let staged = destination
            .stage_private_copy("rootfs.ext4", &source, 3 * 1024 * 1024, 0o400)
            .unwrap();
        assert_eq!(staged.identity().size, expected.len() as u64);
        assert_eq!(
            std::fs::read(destination_root.join("rootfs.ext4")).unwrap(),
            expected
        );
        assert!(
            destination
                .stage_private_copy("rootfs.ext4", &source, 3 * 1024 * 1024, 0o400)
                .is_err()
        );
        std::fs::remove_dir_all(source_root).unwrap();
        std::fs::remove_dir_all(displaced_source_root).unwrap();
        std::fs::remove_dir_all(destination_root).unwrap();
    }
}
