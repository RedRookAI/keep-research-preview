#![forbid(unsafe_code)]

//! Non-authorizing Linux transport primitives for the A6 native boundary.
//!
//! This checkpoint deliberately exposes no launcher, credential, network, profile,
//! evidence, or Firecracker authority. It proves only that the selected safe wrapper
//! reaches the exact kernel primitives required by the reviewed transport decision.

#[cfg(target_os = "linux")]
mod linux {
    use keep_native_protocol::{
        Limits, PROTOCOL_NAME, PROTOCOL_VERSION, Schema, TrustClass, Value, decode_canonical,
        encode_bounded, native_boundary_request_digest, sha256_hex, validate_for,
    };
    use nix::getsockopt_impl;
    use nix::libc;
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use nix::sys::socket::{
        AddressFamily, MsgFlags, SockFlag, SockType, getsockopt, recvmsg, send, socketpair, sockopt,
    };
    use rustix::net::{
        AddressFamily as RustixAddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags,
        ReturnFlags, SendFlags, SocketAddrUnix, SocketFlags, SocketType as RustixSocketType,
        accept_with, bind, connect, listen, recvmsg as rustix_recvmsg, send as rustix_send,
        socket_with,
    };
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::io::{IoSliceMut, Read, Write};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub const MAX_FRAME_BYTES: usize = 65_536;
    pub(super) const MAX_SCM_RIGHTS: usize = 253;
    const MAX_PEER_EXECUTABLE_BYTES: usize = 32 * 1024 * 1024;
    const SUPERVISOR_REQUEST_TIMEOUT_MS: u16 = 2_000;

    nix::sockopt_impl!(
        PeerSecurity,
        GetOnly,
        nix::libc::SOL_SOCKET,
        nix::libc::SO_PEERSEC,
        OsString,
        nix::sys::socket::sockopt::GetOsString<[u8; 4096]>
    );

    pub(super) fn peer_security_label(fd: &OwnedFd) -> Result<OsString, String> {
        getsockopt(fd, PeerSecurity).map_err(|error| format!("SO_PEERSEC: {error}"))
    }

    fn require_live_pidfd(pidfd: &OwnedFd) -> Result<(), String> {
        let mut descriptors = [PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
        if poll(&mut descriptors, PollTimeout::ZERO)
            .map_err(|error| format!("peer pidfd poll: {error}"))?
            != 0
        {
            return Err("peer pidfd is not live".to_owned());
        }
        Ok(())
    }

    pub(super) fn require_procfs(path: &Path) -> Result<(), String> {
        let filesystem =
            nix::sys::statfs::statfs(path).map_err(|error| format!("procfs identity: {error}"))?;
        if filesystem.filesystem_type() != nix::sys::statfs::PROC_SUPER_MAGIC {
            return Err("procfs identity mismatch".to_owned());
        }
        Ok(())
    }

    pub fn sha256_file_bounded(path: &Path) -> Result<String, String> {
        sha256_file_bounded_with_metadata(path).map(|(digest, _)| digest)
    }

    fn sha256_file_bounded_with_metadata(path: &Path) -> Result<(String, fs::Metadata), String> {
        let file = fs::File::open(path).map_err(|error| format!("open measured file: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("measured file metadata: {error}"))?;
        let mut bytes = Vec::new();
        file.take((MAX_PEER_EXECUTABLE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read measured file: {error}"))?;
        if bytes.is_empty() || bytes.len() > MAX_PEER_EXECUTABLE_BYTES {
            return Err("measured file length is invalid".to_owned());
        }
        Ok((sha256_hex(&bytes), metadata))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SeqpacketProbe {
        pub peer_pid: i32,
        pub peer_uid: u32,
        pub peer_gid: u32,
        pub peer_security_label_nonempty: bool,
        pub pidfd_cloexec: bool,
        pub truncation_reported: bool,
        pub full_packet_bytes: usize,
        pub copied_packet_bytes: usize,
    }

    pub fn probe_seqpacket_peer() -> Result<SeqpacketProbe, String> {
        let (left, right) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .map_err(|error| format!("socketpair: {error}"))?;

        let peer = getsockopt(&left, sockopt::PeerCredentials)
            .map_err(|error| format!("SO_PEERCRED: {error}"))?;
        let peer_pidfd = getsockopt(&left, sockopt::PeerPidfd)
            .map_err(|error| format!("SO_PEERPIDFD: {error}"))?;
        let peer_security_label_nonempty = !peer_security_label(&left)?.is_empty();
        let pidfd_flags = nix::fcntl::fcntl(&peer_pidfd, nix::fcntl::FcntlArg::F_GETFD)
            .map_err(|error| format!("pidfd F_GETFD: {error}"))?;
        let pidfd_cloexec = nix::fcntl::FdFlag::from_bits_truncate(pidfd_flags)
            .contains(nix::fcntl::FdFlag::FD_CLOEXEC);

        let payload = b"keep-seqpacket";
        let sent = send(right.as_raw_fd(), payload, MsgFlags::empty())
            .map_err(|error| format!("send seqpacket: {error}"))?;
        if sent != payload.len() {
            return Err("seqpacket send was partial".to_owned());
        }

        let mut copied = [0_u8; 4];
        let mut slices = [IoSliceMut::new(&mut copied)];
        let mut ancillary_storage = nix::cmsg_space!([i32; 1]);
        let message = recvmsg::<()>(
            left.as_raw_fd(),
            &mut slices,
            Some(&mut ancillary_storage),
            MsgFlags::MSG_CMSG_CLOEXEC | MsgFlags::MSG_TRUNC,
        )
        .map_err(|error| format!("recvmsg seqpacket: {error}"))?;
        let truncation_reported = message.flags.contains(MsgFlags::MSG_TRUNC);
        let full_packet_bytes = message.bytes;
        for control in message.cmsgs().map_err(|error| format!("cmsgs: {error}"))? {
            if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = control {
                drop(fds);
                return Err("unexpected SCM_RIGHTS".to_owned());
            }
        }

        Ok(SeqpacketProbe {
            peer_pid: peer.pid(),
            peer_uid: peer.uid(),
            peer_gid: peer.gid(),
            peer_security_label_nonempty,
            pidfd_cloexec,
            truncation_reported,
            full_packet_bytes,
            copied_packet_bytes: copied.len(),
        })
    }

    fn check_parent(path: &Path, expected_uid: u32, expected_gid: u32) -> Result<(), String> {
        let parent = path.parent().ok_or("socket path has no parent")?;
        let metadata =
            fs::symlink_metadata(parent).map_err(|error| format!("socket parent: {error}"))?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err("socket parent is not a real directory".to_owned());
        }
        if metadata.uid() != expected_uid || metadata.gid() != expected_gid {
            return Err("socket parent ownership mismatch".to_owned());
        }
        if metadata.mode() & 0o077 != 0 {
            return Err("socket parent must not grant group/other access".to_owned());
        }
        Ok(())
    }

    fn check_socket(path: &Path, expected_uid: u32, expected_gid: u32) -> Result<(), String> {
        let metadata =
            fs::symlink_metadata(path).map_err(|error| format!("socket metadata: {error}"))?;
        if !metadata.file_type().is_socket() || metadata.file_type().is_symlink() {
            return Err("transport endpoint is not a real socket".to_owned());
        }
        if metadata.uid() != expected_uid || metadata.gid() != expected_gid {
            return Err("socket ownership mismatch".to_owned());
        }
        if metadata.mode() & 0o077 != 0 {
            return Err("socket must not grant group/other access".to_owned());
        }
        Ok(())
    }

    pub(super) fn verify_peer(
        fd: &OwnedFd,
        expected_uid: u32,
        expected_gid: u32,
        expected_security_label: &OsStr,
        expected_executable_sha256: Option<&str>,
        expected_executable_device: Option<u64>,
    ) -> Result<(), String> {
        let credentials = getsockopt(fd, sockopt::PeerCredentials)
            .map_err(|error| format!("SO_PEERCRED: {error}"))?;
        if credentials.uid() != expected_uid || credentials.gid() != expected_gid {
            return Err("peer credentials mismatch".to_owned());
        }
        if expected_security_label.is_empty() {
            return Err("expected peer security label is empty".to_owned());
        }
        if peer_security_label(fd)?.as_os_str() != expected_security_label {
            return Err("peer security label mismatch".to_owned());
        }
        let pidfd =
            getsockopt(fd, sockopt::PeerPidfd).map_err(|error| format!("SO_PEERPIDFD: {error}"))?;
        let flags = nix::fcntl::fcntl(&pidfd, nix::fcntl::FcntlArg::F_GETFD)
            .map_err(|error| format!("peer pidfd F_GETFD: {error}"))?;
        if !nix::fcntl::FdFlag::from_bits_truncate(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC) {
            return Err("peer pidfd is not CLOEXEC".to_owned());
        }
        require_live_pidfd(&pidfd)?;
        if let Some(expected) = expected_executable_sha256 {
            if expected.len() != 64
                || !expected
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err("expected peer executable digest is malformed".to_owned());
            }
            require_procfs(Path::new("/proc"))?;
            let executable = PathBuf::from(format!("/proc/{}/exe", credentials.pid()));
            let (digest, metadata) = sha256_file_bounded_with_metadata(&executable)?;
            if let Some(device) = expected_executable_device {
                if metadata.dev() != device
                    || metadata.uid() != 0
                    || metadata.gid() != 0
                    || metadata.mode() & 0o022 != 0
                {
                    return Err("peer executable package identity mismatch".to_owned());
                }
            }
            if digest != expected {
                return Err("peer executable measurement mismatch".to_owned());
            }
            require_live_pidfd(&pidfd)?;
        }
        Ok(())
    }

    pub(super) fn receive_packet(fd: &OwnedFd) -> Result<Vec<u8>, String> {
        let mut bytes = vec![0_u8; MAX_FRAME_BYTES];
        let mut iov = [IoSliceMut::new(&mut bytes)];
        let mut control_storage =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_SCM_RIGHTS))];
        let mut control = RecvAncillaryBuffer::new(&mut control_storage);
        let message = rustix_recvmsg(
            fd,
            &mut iov,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC,
        )
        .map_err(|error| format!("recvmsg: {error}"))?;
        let mut received_rights = false;
        for ancillary in control.drain() {
            if let RecvAncillaryMessage::ScmRights(rights) = ancillary {
                received_rights = true;
                drop(rights.collect::<Vec<_>>());
            } else {
                return Err("unexpected ancillary message".to_owned());
            }
        }
        if received_rights {
            return Err("SCM_RIGHTS is forbidden".to_owned());
        }
        if message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            || message.bytes > MAX_FRAME_BYTES
        {
            return Err("transport packet was truncated".to_owned());
        }
        bytes.truncate(message.bytes);
        if bytes.is_empty() {
            return Err("transport packet is empty".to_owned());
        }
        Ok(bytes)
    }

    fn wait_for_supervisor_request(fd: &OwnedFd) -> Result<(), String> {
        let mut descriptors = [PollFd::new(
            fd.as_fd(),
            PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
        )];
        let ready = poll(
            &mut descriptors,
            PollTimeout::from(SUPERVISOR_REQUEST_TIMEOUT_MS),
        )
        .map_err(|error| format!("request readiness poll: {error}"))?;
        if ready == 0 {
            return Err("connected peer request timed out".to_owned());
        }
        Ok(())
    }

    pub(super) fn reject_queued_packet(fd: &OwnedFd) -> Result<(), String> {
        let mut byte = [0_u8; 1];
        let mut iov = [IoSliceMut::new(&mut byte)];
        let mut control_storage =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_SCM_RIGHTS))];
        let mut control = RecvAncillaryBuffer::new(&mut control_storage);
        let message = match rustix_recvmsg(
            fd,
            &mut iov,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT | RecvFlags::PEEK | RecvFlags::TRUNC,
        ) {
            Err(rustix::io::Errno::AGAIN) => return Ok(()),
            Err(error) => return Err(format!("peek next packet: {error}")),
            Ok(message) => message,
        };
        for ancillary in control.drain() {
            if let RecvAncillaryMessage::ScmRights(rights) = ancillary {
                drop(rights.collect::<Vec<_>>());
            }
        }
        let _ = message;
        Err("multiple transport packets are forbidden".to_owned())
    }

    fn send_packet(fd: &OwnedFd, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err("transport packet length is invalid".to_owned());
        }
        let sent =
            rustix_send(fd, bytes, SendFlags::empty()).map_err(|error| format!("send: {error}"))?;
        if sent != bytes.len() {
            return Err("seqpacket send was partial".to_owned());
        }
        Ok(())
    }

    fn required(value: &Value, key: &str) -> Result<Value, String> {
        value
            .field(key)
            .cloned()
            .ok_or_else(|| format!("request field missing: {key}"))
    }

    fn refusal_for(request_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let request =
            decode_canonical(request_bytes, Limits::WIRE).map_err(|error| error.to_string())?;
        if validate_for(&request, TrustClass::Development).map_err(|error| error.to_string())?
            != Schema::Request
            || request.field("kind").and_then(Value::as_text) != Some("cancel")
        {
            return Err("development transport accepts only cancel requests".to_owned());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock precedes Unix epoch")?
            .as_millis();
        if u128::from(
            required(&request, "deadlineMs")?
                .as_u64()
                .ok_or("deadline is not an integer")?,
        ) <= now
        {
            return Err("request deadline expired".to_owned());
        }
        let executable =
            std::env::current_exe().map_err(|error| format!("current executable: {error}"))?;
        let artifact =
            fs::read(executable).map_err(|error| format!("read current executable: {error}"))?;
        let kernel_boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| format!("kernel boot id: {error}"))?
            .trim()
            .to_owned();
        let response = Value::Map(vec![
            ("protocol".into(), Value::Text(PROTOCOL_NAME.into())),
            ("version".into(), Value::Unsigned(PROTOCOL_VERSION)),
            ("requestId".into(), required(&request, "requestId")?),
            (
                "requestDigest".into(),
                Value::Text(
                    native_boundary_request_digest(&request).map_err(|error| error.to_string())?,
                ),
            ),
            ("deploymentId".into(), required(&request, "deploymentId")?),
            ("bootId".into(), required(&request, "bootId")?),
            ("nonce".into(), required(&request, "nonce")?),
            ("sequence".into(), required(&request, "sequence")?),
            (
                "helperArtifactDigest".into(),
                Value::Text(sha256_hex(&artifact)),
            ),
            (
                "helperBuildId".into(),
                Value::Text("development.transport.v1".into()),
            ),
            ("kernelBootId".into(), Value::Text(kernel_boot_id)),
            ("status".into(), Value::Text("refused".into())),
            ("roleHandles".into(), Value::Array(Vec::new())),
            ("measurements".into(), Value::Array(Vec::new())),
            (
                "failureCode".into(),
                Value::Text("evidence.unavailable.transport_only".into()),
            ),
            ("evidenceBundleDigest".into(), Value::Null),
        ]);
        if validate_for(&response, TrustClass::Development).map_err(|error| error.to_string())?
            != Schema::Response
        {
            return Err("constructed refusal is not a response".to_owned());
        }
        encode_bounded(&response, Limits::WIRE).map_err(|error| error.to_string())
    }

    pub(super) struct SocketPathGuard {
        path: PathBuf,
        device: u64,
        inode: u64,
    }

    impl SocketPathGuard {
        pub(super) fn capture(path: &Path) -> Result<Self, String> {
            let metadata = fs::symlink_metadata(path)
                .map_err(|error| format!("capture bound socket: {error}"))?;
            if !metadata.file_type().is_socket() || metadata.file_type().is_symlink() {
                return Err("bound endpoint is not a real socket".to_owned());
            }
            Ok(Self {
                path: path.to_path_buf(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
    }

    impl Drop for SocketPathGuard {
        fn drop(&mut self) {
            let Ok(metadata) = fs::symlink_metadata(&self.path) else {
                return;
            };
            if metadata.dev() == self.device && metadata.ino() == self.inode {
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    pub fn serve_one_refusal(
        path: &Path,
        expected_client_uid: u32,
        expected_client_gid: u32,
        expected_client_security_label: &OsStr,
    ) -> Result<(), String> {
        check_parent(
            path,
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )?;
        if fs::symlink_metadata(path).is_ok() {
            return Err("socket path already exists".to_owned());
        }
        let listener = socket_with(
            RustixAddressFamily::UNIX,
            RustixSocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|error| format!("socket: {error}"))?;
        let address =
            SocketAddrUnix::new(path).map_err(|error| format!("socket address: {error}"))?;
        bind(&listener, &address).map_err(|error| format!("bind: {error}"))?;
        let _guard = SocketPathGuard::capture(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("socket permissions: {error}"))?;
        listen(&listener, 1).map_err(|error| format!("listen: {error}"))?;
        let peer = accept_with(&listener, SocketFlags::CLOEXEC)
            .map_err(|error| format!("accept: {error}"))?;
        verify_peer(
            &peer,
            expected_client_uid,
            expected_client_gid,
            expected_client_security_label,
            None,
            None,
        )?;
        wait_for_supervisor_request(&peer)?;
        let request = receive_packet(&peer)?;
        reject_queued_packet(&peer)?;
        send_packet(&peer, &refusal_for(&request)?)
    }

    pub fn exchange_refusal(
        path: &Path,
        expected_server_uid: u32,
        expected_server_gid: u32,
        expected_server_security_label: &OsStr,
        expected_server_executable_sha256: &str,
        expected_server_executable_device: Option<u64>,
        request: &[u8],
    ) -> Result<Vec<u8>, String> {
        check_parent(path, expected_server_uid, expected_server_gid)?;
        check_socket(path, expected_server_uid, expected_server_gid)?;
        let peer = socket_with(
            RustixAddressFamily::UNIX,
            RustixSocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|error| format!("socket: {error}"))?;
        let address =
            SocketAddrUnix::new(path).map_err(|error| format!("socket address: {error}"))?;
        connect(&peer, &address).map_err(|error| format!("connect: {error}"))?;
        verify_peer(
            &peer,
            expected_server_uid,
            expected_server_gid,
            expected_server_security_label,
            Some(expected_server_executable_sha256),
            expected_server_executable_device,
        )?;
        send_packet(&peer, request)?;
        receive_packet(&peer)
    }

    pub fn read_framed(input: impl Read) -> Result<Vec<u8>, String> {
        let mut framed = Vec::new();
        input
            .take((MAX_FRAME_BYTES + 5) as u64)
            .read_to_end(&mut framed)
            .map_err(|error| format!("read frame: {error}"))?;
        if framed.len() < 4 {
            return Err("frame header is truncated".to_owned());
        }
        let length = u32::from_be_bytes(framed[..4].try_into().expect("four-byte header")) as usize;
        if length == 0 || length > MAX_FRAME_BYTES || framed.len() != length + 4 {
            return Err("frame length is invalid".to_owned());
        }
        Ok(framed.split_off(4))
    }

    pub fn write_framed(mut output: impl Write, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err("frame length is invalid".to_owned());
        }
        output
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .map_err(|error| format!("write frame: {error}"))?;
        output
            .write_all(bytes)
            .map_err(|error| format!("write frame: {error}"))?;
        output
            .flush()
            .map_err(|error| format!("flush frame: {error}"))
    }
}

#[cfg(target_os = "linux")]
pub use linux::{
    MAX_FRAME_BYTES, SeqpacketProbe, exchange_refusal, probe_seqpacket_peer, read_framed,
    serve_one_refusal, sha256_file_bounded, write_framed,
};

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    fn descriptor_count_for_target(descriptor: std::os::fd::RawFd) -> usize {
        let target =
            std::fs::read_link(format!("/proc/self/fd/{descriptor}")).expect("descriptor target");
        std::fs::read_dir("/proc/self/fd")
            .expect("fd directory")
            .filter_map(Result::ok)
            .filter(|entry| std::fs::read_link(entry.path()).ok().as_ref() == Some(&target))
            .count()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executable_measurement_refuses_a_non_proc_filesystem_view() {
        assert_eq!(
            super::linux::require_procfs(&std::env::temp_dir()),
            Err("procfs identity mismatch".to_owned())
        );
        assert_eq!(
            super::linux::require_procfs(std::path::Path::new("/proc")),
            Ok(())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executable_measurement_refuses_bytes_beyond_its_ceiling() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("keep-oversize-executable-{nonce}"));
        let file = fs::File::create(&path).expect("create measured file");
        file.set_len((32 * 1024 * 1024 + 1) as u64)
            .expect("extend measured file beyond ceiling");
        drop(file);
        assert_eq!(
            super::sha256_file_bounded(&path),
            Err("measured file length is invalid".to_owned())
        );
        fs::remove_file(path).expect("remove measured file");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oversized_kernel_packet_is_rejected_without_prefix_parsing() {
        use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, send, socketpair};
        use std::os::fd::AsRawFd;

        let (receiver, sender) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("seqpacket pair");
        let oversized = vec![7_u8; super::MAX_FRAME_BYTES + 1];
        assert_eq!(
            send(sender.as_raw_fd(), &oversized, MsgFlags::empty()).expect("send hostile packet"),
            oversized.len()
        );
        assert_eq!(
            super::linux::receive_packet(&receiver),
            Err("transport packet was truncated".to_owned())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn received_scm_rights_are_closed_and_rejected() {
        use nix::sys::socket::{
            AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, sendmsg, socketpair,
        };
        use std::io::IoSlice;
        use std::os::fd::AsRawFd;

        let (receiver, sender) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("seqpacket pair");
        let payload = [IoSlice::new(b"forbidden-right")];
        let rights = [receiver.as_raw_fd()];
        assert_eq!(
            sendmsg::<()>(
                sender.as_raw_fd(),
                &payload,
                &[ControlMessage::ScmRights(&rights)],
                MsgFlags::empty(),
                None,
            )
            .expect("send hostile rights"),
            b"forbidden-right".len()
        );
        assert_eq!(
            super::linux::receive_packet(&receiver),
            Err("SCM_RIGHTS is forbidden".to_owned())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn queued_packet_peek_closes_maximum_attached_rights() {
        use nix::sys::socket::{
            AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, sendmsg, socketpair,
        };
        use std::io::IoSlice;
        use std::os::fd::AsRawFd;

        let (receiver, sender) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("seqpacket pair");
        let baseline = descriptor_count_for_target(sender.as_raw_fd());
        let payload = [IoSlice::new(b"queued-rights")];
        let rights = [sender.as_raw_fd(); super::linux::MAX_SCM_RIGHTS];
        assert_eq!(
            sendmsg::<()>(
                sender.as_raw_fd(),
                &payload,
                &[ControlMessage::ScmRights(&rights)],
                MsgFlags::empty(),
                None,
            )
            .expect("queue maximum rights"),
            b"queued-rights".len()
        );
        assert_eq!(
            super::linux::reject_queued_packet(&receiver),
            Err("multiple transport packets are forbidden".to_owned())
        );
        let after = descriptor_count_for_target(sender.as_raw_fd());
        assert_eq!(after, baseline, "queued-packet peek leaked descriptors");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn maximum_scm_rights_cannot_leak_or_exhaust_descriptors() {
        use nix::sys::socket::{
            AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, sendmsg, socketpair,
        };
        use std::io::IoSlice;
        use std::os::fd::AsRawFd;

        let (receiver, sender) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("seqpacket pair");
        let baseline = descriptor_count_for_target(receiver.as_raw_fd());
        let payload = [IoSlice::new(b"ancillary-overflow")];
        let rights = [receiver.as_raw_fd(); super::linux::MAX_SCM_RIGHTS];
        assert_eq!(
            sendmsg::<()>(
                sender.as_raw_fd(),
                &payload,
                &[ControlMessage::ScmRights(&rights)],
                MsgFlags::empty(),
                None,
            )
            .expect("send hostile rights overflow"),
            b"ancillary-overflow".len()
        );
        assert!(super::linux::receive_packet(&receiver).is_err());
        let after = descriptor_count_for_target(receiver.as_raw_fd());
        assert_eq!(after, baseline, "ancillary receipt leaked descriptors");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_seqpacket_peer_identity_and_truncation_are_available() {
        let probe = super::probe_seqpacket_peer().expect("measured Linux transport cell");
        assert_eq!(probe.peer_pid, std::process::id() as i32);
        assert_eq!(probe.peer_uid, nix::unistd::geteuid().as_raw());
        assert_eq!(probe.peer_gid, nix::unistd::getegid().as_raw());
        assert!(probe.peer_security_label_nonempty);
        assert!(probe.pidfd_cloexec, "SO_PEERPIDFD must return a CLOEXEC fd");
        assert!(
            probe.truncation_reported,
            "short receive must report MSG_TRUNC"
        );
        assert_eq!(probe.full_packet_bytes, b"keep-seqpacket".len());
        assert_eq!(probe.copied_packet_bytes, 4);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_seqpacket_peer_security_label_is_available_atomically() {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

        let (left, _right) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .expect("seqpacket pair");
        let label = super::linux::peer_security_label(&left).expect("SO_PEERSEC label");
        assert!(!label.is_empty(), "SO_PEERSEC label must not be empty");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dead_connected_peer_cannot_pass_pidfd_admission() {
        use rustix::net::{
            AddressFamily, SocketAddrUnix, SocketFlags, SocketType, accept_with, bind, listen,
            socket_with,
        };
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("keep-dead-peer-{nonce}"));
        fs::create_dir(&directory).expect("create private directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("private directory mode");
        let path = directory.join("peer.sock");
        let listener = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("listener socket");
        bind(
            &listener,
            &SocketAddrUnix::new(&path).expect("socket address"),
        )
        .expect("bind");
        listen(&listener, 1).expect("listen");
        let code = "import socket,sys,time\ns=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)\ns.connect(sys.argv[1])\ntime.sleep(60)";
        let mut child = Command::new("/usr/bin/python3")
            .args(["-c", code, path.to_str().expect("socket path")])
            .spawn()
            .expect("spawn connected peer");
        let peer = accept_with(&listener, SocketFlags::CLOEXEC).expect("accept peer");
        child.kill().expect("kill connected peer");
        child.wait().expect("reap connected peer");
        let label = fs::read_to_string("/proc/self/attr/current")
            .expect("security label")
            .trim_end_matches(['\0', '\n'])
            .to_owned();
        let error = super::linux::verify_peer(
            &peer,
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
            label.as_ref(),
            None,
            None,
        )
        .expect_err("dead peer must not pass identity admission");
        assert!(
            error.contains("SO_PEERPIDFD") || error.contains("not live"),
            "{error}"
        );
        drop(peer);
        drop(listener);
        fs::remove_file(path).expect("remove socket");
        fs::remove_dir(directory).expect("remove directory");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_cleanup_guard_cannot_unlink_a_successor_inode() {
        use std::fs;
        use std::os::unix::net::UnixDatagram;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("keep-socket-guard-{nonce}"));
        fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("native.sock");
        let displaced = directory.join("displaced.sock");
        let original = UnixDatagram::bind(&path).expect("bind original socket");
        let guard = super::linux::SocketPathGuard::capture(&path).expect("capture original");
        fs::rename(&path, &displaced).expect("displace original socket");
        let successor = UnixDatagram::bind(&path).expect("bind successor socket");
        drop(guard);
        assert!(path.exists(), "guard unlinked the successor socket");
        drop(successor);
        drop(original);
        fs::remove_file(path).expect("remove successor");
        fs::remove_file(displaced).expect("remove displaced original");
        fs::remove_dir(directory).expect("remove test directory");
    }
}
