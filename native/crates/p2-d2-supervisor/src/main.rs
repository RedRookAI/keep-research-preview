#![forbid(unsafe_code)]

use keep_native_linux_abi::{
    LandlockRuleset, install_objective3_seccomp_filter, no_new_privileges_active,
};
use std::fs::File;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::process::CommandExt;
use std::process::Command;

fn fail(message: &str) -> ! {
    eprintln!("keep P2-D2 build cell: {message}");
    std::process::exit(125)
}

fn cargo_arguments(mode: &str) -> &'static [&'static str] {
    match mode {
        "metadata-unlocked" => &["metadata", "--offline", "--format-version", "1"],
        "metadata-locked" => &["metadata", "--locked", "--offline", "--format-version", "1"],
        "check" => &[
            "check",
            "--locked",
            "--offline",
            "--frozen",
            "--all-targets",
            "--message-format=json",
        ],
        _ => fail("unknown closed command mode"),
    }
}

fn main() {
    let mut arguments = std::env::args();
    let _program = arguments.next();
    let mode = arguments
        .next()
        .unwrap_or_else(|| fail("one command mode is required"));
    if arguments.next().is_some() {
        fail("extra arguments are forbidden");
    }

    let read_only_paths = [
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
        "/proc",
        "/keep/toolchain",
        "/keep/vendor",
        "/keep/result",
    ];
    let read_write_paths = ["/work", "/tmp", "/dev"];
    let read_only = read_only_paths
        .map(|path| File::open(path).unwrap_or_else(|_| fail("required read-only root is absent")));
    let read_write = read_write_paths
        .map(|path| File::open(path).unwrap_or_else(|_| fail("required writable root is absent")));
    let ruleset = LandlockRuleset::new(4)
        .unwrap_or_else(|_| fail("Landlock ABI or ruleset construction refused"));
    for path in &read_only {
        ruleset
            .allow_read_only(path)
            .unwrap_or_else(|_| fail("read-only Landlock rule refused"));
    }
    for path in &read_write {
        ruleset
            .allow_read_write(path)
            .unwrap_or_else(|_| fail("read-write Landlock rule refused"));
    }
    let landlock_abi = ruleset
        .restrict_self()
        .unwrap_or_else(|_| fail("Landlock activation refused"));
    install_objective3_seccomp_filter().unwrap_or_else(|_| fail("seccomp activation refused"));
    let status = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_else(|_| fail("post-confinement process status is unreadable"));
    let seccomp_mode = status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp:\t"))
        .unwrap_or_else(|| fail("post-confinement seccomp measurement is absent"));
    let capabilities_are_zero = [
        "CapInh:\t",
        "CapPrm:\t",
        "CapEff:\t",
        "CapBnd:\t",
        "CapAmb:\t",
    ]
    .iter()
    .all(|prefix| {
        status
            .lines()
            .any(|line| line.strip_prefix(prefix) == Some("0000000000000000"))
    });
    if !no_new_privileges_active().unwrap_or(false) || seccomp_mode != "2" || !capabilities_are_zero
    {
        fail("post-confinement privilege/seccomp/capability measurement disagreed");
    }
    eprintln!(
        "[keep-p2-d2-cell] mode={mode} landlockAbi={landlock_abi} noNewPrivs=1 seccomp=2 capabilities=zero"
    );
    if mode == "probe-network" {
        if TcpListener::bind("0.0.0.0:0").is_ok() || TcpStream::connect("198.51.100.1:443").is_ok()
        {
            fail("Landlock admitted a forbidden TCP operation");
        }
        let udp = UdpSocket::bind("0.0.0.0:0")
            .unwrap_or_else(|_| fail("local UDP probe socket construction failed"));
        if udp.connect("198.51.100.1:53").is_ok() && udp.send(b"keep-network-refusal").is_ok() {
            fail("isolated network namespace admitted an external UDP datagram");
        }
        return;
    }

    let mut cargo = Command::new("/keep/toolchain/bin/cargo");
    cargo.args(cargo_arguments(&mode));
    cargo.current_dir("/work");
    cargo.env_clear();
    cargo.envs([
        ("PATH", "/keep/toolchain/bin:/usr/bin:/bin"),
        ("HOME", "/work/.home"),
        ("LANG", "C"),
        ("LC_ALL", "C"),
        ("TZ", "UTC"),
        ("SOURCE_DATE_EPOCH", "0"),
        ("RUSTUP_TOOLCHAIN", "1.97.1-x86_64-unknown-linux-gnu"),
        ("CARGO_HOME", "/work/.cargo-home"),
        ("CARGO_NET_OFFLINE", "true"),
        ("CARGO_INCREMENTAL", "0"),
        ("CARGO_TARGET_DIR", "/work/target"),
        ("RUSTC", "/keep/toolchain/bin/rustc"),
        ("RUSTDOC", "/keep/toolchain/bin/rustdoc"),
        (
            "RUSTFLAGS",
            "--cfg=curve25519_dalek_backend=\"fiat\" --cfg=curve25519_dalek_bits=\"64\"",
        ),
    ]);
    let error = cargo.exec();
    fail(&format!("Cargo exec failed: {error}"));
}
