#![forbid(unsafe_code)]

use keep_native_protocol::{
    Limits, PROTOCOL_NAME, PROTOCOL_VERSION, Schema, TrustClass, Value, decode_canonical,
    encode_bounded, native_boundary_request_digest, validate_for,
};
use keep_native_transport::{exchange_refusal, read_framed, serve_one_refusal, write_framed};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("keep-transport-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).expect("create private test directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("set private test directory mode");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn request() -> Value {
    let deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock")
        .as_millis() as u64
        + 60_000;
    Value::Map(vec![
        ("protocol".into(), Value::Text(PROTOCOL_NAME.into())),
        ("version".into(), Value::Unsigned(PROTOCOL_VERSION)),
        ("kind".into(), Value::Text("cancel".into())),
        ("requestId".into(), Value::Text("transport.request".into())),
        (
            "deploymentId".into(),
            Value::Text("development.deployment".into()),
        ),
        ("bootId".into(), Value::Text("development.boot".into())),
        ("manifestDigest".into(), Value::Text("11".repeat(32))),
        ("nonce".into(), Value::Text("transport.nonce".into())),
        ("sequence".into(), Value::Unsigned(7)),
        ("deadlineMs".into(), Value::Unsigned(deadline)),
        (
            "targetRequestId".into(),
            Value::Text("transport.target".into()),
        ),
    ])
}

fn current_security_label() -> String {
    fs::read_to_string("/proc/self/attr/current")
        .expect("read current security label")
        .trim_end_matches(['\0', '\n'])
        .to_owned()
}

fn current_executable_digest() -> String {
    keep_native_transport::sha256_file_bounded(
        &std::env::current_exe().expect("current test executable"),
    )
    .expect("hash current test executable")
}

fn wait_for_path(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "supervisor socket did not appear"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_child(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("child process timed out");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn separate_binaries_exchange_only_a_schema_valid_transport_refusal() {
    let directory = TestDirectory::new();
    let socket = directory.0.join("native.sock");
    let uid = nix::unistd::geteuid().as_raw().to_string();
    let gid = nix::unistd::getegid().as_raw().to_string();
    let security_label = current_security_label();

    let mut supervisor = Command::new(env!("CARGO_BIN_EXE_keep-native-supervisor"))
        .args([
            "--socket",
            socket.to_str().expect("socket path"),
            "--expected-client-uid",
            &uid,
            "--expected-client-gid",
            &gid,
            "--expected-client-security-label",
            &security_label,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn supervisor");
    wait_for_path(&socket, Duration::from_secs(2));

    let request = request();
    let canonical_request = encode_bounded(&request, Limits::WIRE).expect("canonical request");
    let mut client = Command::new(env!("CARGO_BIN_EXE_keep-native-client"))
        .args([
            "--socket",
            socket.to_str().expect("socket path"),
            "--expected-server-uid",
            &uid,
            "--expected-server-gid",
            &gid,
            "--expected-server-security-label",
            &security_label,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn client");
    write_framed(
        client.stdin.take().expect("client stdin"),
        &canonical_request,
    )
    .expect("write request frame");
    let client_status = wait_child(&mut client, Duration::from_secs(5));
    let client_output = client.wait_with_output().expect("collect client output");
    assert!(
        client_status.success(),
        "client stderr: {}",
        String::from_utf8_lossy(&client_output.stderr)
    );
    let supervisor_status = wait_child(&mut supervisor, Duration::from_secs(2));
    let supervisor_output = supervisor
        .wait_with_output()
        .expect("collect supervisor output");
    assert!(
        supervisor_status.success(),
        "supervisor stderr: {}",
        String::from_utf8_lossy(&supervisor_output.stderr)
    );

    let response_bytes = read_framed(client_output.stdout.as_slice()).expect("read response frame");
    let response = decode_canonical(&response_bytes, Limits::WIRE).expect("canonical response");
    assert_eq!(
        validate_for(&response, TrustClass::Development),
        Ok(Schema::Response)
    );
    assert_eq!(
        response.field("status").and_then(Value::as_text),
        Some("refused")
    );
    assert_eq!(
        response.field("failureCode").and_then(Value::as_text),
        Some("evidence.unavailable.transport_only")
    );
    assert_eq!(response.field("evidenceBundleDigest"), Some(&Value::Null));
    assert_eq!(
        response.field("roleHandles"),
        Some(&Value::Array(Vec::new()))
    );
    assert_eq!(
        response.field("measurements"),
        Some(&Value::Array(Vec::new()))
    );
    assert_eq!(
        response.field("requestDigest").and_then(Value::as_text),
        Some(
            native_boundary_request_digest(&request)
                .expect("request digest")
                .as_str()
        )
    );
}

#[test]
fn stdio_framing_rejects_truncation_trailing_bytes_and_oversize() {
    assert!(read_framed([0, 0, 0].as_slice()).is_err());
    assert!(read_framed([0, 0, 0, 1, 7, 8].as_slice()).is_err());
    let mut oversize = ((keep_native_transport::MAX_FRAME_BYTES + 1) as u32)
        .to_be_bytes()
        .to_vec();
    oversize.write_all(&[0]).expect("extend hostile frame");
    assert!(read_framed(oversize.as_slice()).is_err());
}

#[test]
fn server_refuses_a_connected_peer_with_the_wrong_expected_identity() {
    let directory = TestDirectory::new();
    let socket = directory.0.join("wrong-peer.sock");
    let actual_uid = nix::unistd::geteuid().as_raw();
    let actual_gid = nix::unistd::getegid().as_raw();
    let security_label = current_security_label();
    let wrong_uid = if actual_uid == u32::MAX {
        actual_uid - 1
    } else {
        actual_uid + 1
    };
    let server_socket = socket.clone();
    let server_label = security_label.clone();
    let server = thread::spawn(move || {
        serve_one_refusal(&server_socket, wrong_uid, actual_gid, server_label.as_ref())
    });
    wait_for_path(&socket, Duration::from_secs(2));
    let request = encode_bounded(&request(), Limits::WIRE).expect("canonical request");
    assert!(
        exchange_refusal(
            &socket,
            actual_uid,
            actual_gid,
            security_label.as_ref(),
            &current_executable_digest(),
            None,
            &request,
        )
        .is_err()
    );
    assert_eq!(
        server.join().expect("server thread"),
        Err("peer credentials mismatch".to_owned())
    );
}

#[test]
fn server_refuses_a_connected_peer_with_the_wrong_security_label() {
    let directory = TestDirectory::new();
    let socket = directory.0.join("wrong-label.sock");
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let actual_label = current_security_label();
    let server_socket = socket.clone();
    let server = thread::spawn(move || {
        serve_one_refusal(
            &server_socket,
            uid,
            gid,
            "keep.invalid.security.label".as_ref(),
        )
    });
    wait_for_path(&socket, Duration::from_secs(2));
    let request = encode_bounded(&request(), Limits::WIRE).expect("canonical request");
    assert!(
        exchange_refusal(
            &socket,
            uid,
            gid,
            actual_label.as_ref(),
            &current_executable_digest(),
            None,
            &request,
        )
        .is_err()
    );
    assert_eq!(
        server.join().expect("server thread"),
        Err("peer security label mismatch".to_owned())
    );
}

#[test]
fn server_refuses_multiple_packets_before_parsing_or_responding() {
    use rustix::net::{
        AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType, connect, send,
        socket_with,
    };

    let directory = TestDirectory::new();
    let socket = directory.0.join("multiple-packets.sock");
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let security_label = current_security_label();
    let server_socket = socket.clone();
    let server_label = security_label.clone();
    let server =
        thread::spawn(move || serve_one_refusal(&server_socket, uid, gid, server_label.as_ref()));
    wait_for_path(&socket, Duration::from_secs(2));
    let peer = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("client socket");
    connect(
        &peer,
        &SocketAddrUnix::new(&socket).expect("socket address"),
    )
    .expect("connect");
    let packet = encode_bounded(&request(), Limits::WIRE).expect("canonical request");
    assert_eq!(
        send(&peer, &packet, SendFlags::empty()).expect("first packet"),
        packet.len()
    );
    assert_eq!(
        send(&peer, &packet, SendFlags::empty()).expect("replay packet"),
        packet.len()
    );
    assert_eq!(
        server.join().expect("server thread"),
        Err("multiple transport packets are forbidden".to_owned())
    );
}

#[test]
fn server_refuses_noncanonical_wire_bytes_before_responding() {
    use rustix::net::{
        AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType, connect, send,
        socket_with,
    };

    let directory = TestDirectory::new();
    let socket = directory.0.join("noncanonical.sock");
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let security_label = current_security_label();
    let server_socket = socket.clone();
    let server_label = security_label.clone();
    let server =
        thread::spawn(move || serve_one_refusal(&server_socket, uid, gid, server_label.as_ref()));
    wait_for_path(&socket, Duration::from_secs(2));
    let peer = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("client socket");
    connect(
        &peer,
        &SocketAddrUnix::new(&socket).expect("socket address"),
    )
    .expect("connect");
    assert_eq!(
        send(&peer, &[0x9f, 0xff], SendFlags::empty()).expect("noncanonical packet"),
        2
    );
    assert!(
        server
            .join()
            .expect("server thread")
            .expect_err("noncanonical bytes must refuse")
            .contains("indefinite")
    );
}

#[test]
fn server_bounds_a_connected_peer_that_never_sends_a_request() {
    use rustix::net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
    };

    let directory = TestDirectory::new();
    let socket = directory.0.join("silent-peer.sock");
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let security_label = current_security_label();
    let server_socket = socket.clone();
    let server_label = security_label.clone();
    let server =
        thread::spawn(move || serve_one_refusal(&server_socket, uid, gid, server_label.as_ref()));
    wait_for_path(&socket, Duration::from_secs(2));
    let peer = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("client socket");
    connect(
        &peer,
        &SocketAddrUnix::new(&socket).expect("socket address"),
    )
    .expect("connect silent peer");
    let started = Instant::now();
    assert_eq!(
        server.join().expect("server thread"),
        Err("connected peer request timed out".to_owned())
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "silent connected peer wedged the one-shot supervisor"
    );
}
