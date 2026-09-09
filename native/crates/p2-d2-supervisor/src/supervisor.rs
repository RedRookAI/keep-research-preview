#![forbid(unsafe_code)]

use keep_native_linux_abi::{
    PinnedDirectory, SealedExecutable, SealedFile, seal_data_file_bytes, seal_executable_bytes,
    seal_file_bytes,
};
use keep_native_protocol::sha256_hex;
use std::collections::BTreeSet;
use std::fs::read_to_string;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const BWRAP_DIGEST: &str = "52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712";
const MEMORY_MAX: &str = "2147483648";
const MEMORY_SWAP_MAX: &str = "0";
const PIDS_MAX: &str = "256";
const CPU_MAX: &str = "400000 100000";
const IO_BYTES_PER_SECOND: &str = "268435456";
const IO_OPERATIONS_PER_SECOND: &str = "4096";
const MANIFEST_MAX_BYTES: u64 = 1024 * 1024;

fn fail(message: &str) -> ! {
    eprintln!("keep P2-D2 supervisor: {message}");
    std::process::exit(125)
}

fn exact_file(path: &Path, expected: &str) {
    let observed =
        read_to_string(path).unwrap_or_else(|_| fail("cgroup control file is unreadable"));
    if observed.trim_end() != expected {
        fail("cgroup control value differs from the frozen Objective 3 ceiling");
    }
}

fn linux_device_numbers(device: u64) -> (u64, u64) {
    let major = ((device >> 8) & 0xfff) | ((device >> 32) & !0xfff);
    let minor = (device & 0xff) | ((device >> 12) & !0xff);
    (major, minor)
}

fn verify_cgroup(unit: &str, work: &Path) {
    if !unit.starts_with("keep-objective3-")
        || !unit.ends_with(".service")
        || unit.len() > 96
        || !unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        fail("transient cgroup unit identity is malformed");
    }
    let expected = format!("0::/system.slice/{unit}\n");
    if read_to_string("/proc/self/cgroup").unwrap_or_default() != expected {
        fail("process is not in the expected systemd cgroup");
    }
    let root = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    exact_file(&root.join("memory.max"), MEMORY_MAX);
    exact_file(&root.join("memory.swap.max"), MEMORY_SWAP_MAX);
    exact_file(&root.join("pids.max"), PIDS_MAX);
    exact_file(&root.join("cpu.max"), CPU_MAX);
    let device = work
        .metadata()
        .unwrap_or_else(|_| fail("work root device identity is unreadable"))
        .dev();
    let (major, minor) = linux_device_numbers(device);
    exact_file(
        &root.join("io.max"),
        &format!(
            "{major}:{minor} rbps={IO_BYTES_PER_SECOND} wbps={IO_BYTES_PER_SECOND} riops={IO_OPERATIONS_PER_SECOND} wiops={IO_OPERATIONS_PER_SECOND}"
        ),
    );
    let limits = read_to_string("/proc/self/limits")
        .unwrap_or_else(|_| fail("process resource limits are unreadable"));
    let open_files = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .unwrap_or_else(|| fail("open-file limit is absent"));
    let values = open_files.split_whitespace().collect::<Vec<_>>();
    if values.get(3..5) != Some(&["4096", "4096"][..]) {
        fail("open-file limit differs from the frozen snapshot ceiling");
    }
}

fn capture_absolute_file(
    path: &str,
    maximum_bytes: u64,
) -> keep_native_linux_abi::CapturedRegularFile {
    let source = Path::new(path);
    let parent = PinnedDirectory::open(
        source
            .parent()
            .unwrap_or_else(|| fail("captured file parent is absent")),
    )
    .unwrap_or_else(|_| fail("captured file parent pinning refused"));
    parent
        .capture_regular_file(
            source
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_else(|| fail("captured file leaf is malformed")),
            maximum_bytes,
        )
        .unwrap_or_else(|_| fail("regular-file capture refused"))
}

fn sealed_snapshot_arguments(
    source_root: &str,
    manifest_path: &str,
    manifest_digest: &str,
    destination_root: &str,
    executable: bool,
    total_maximum: u64,
    sequence: &mut usize,
    sealed_files: &mut Vec<SealedFile>,
) -> Vec<String> {
    let manifest = capture_absolute_file(manifest_path, MANIFEST_MAX_BYTES);
    if sha256_hex(manifest.bytes()) != manifest_digest {
        fail("snapshot manifest digest disagreed");
    }
    let text = std::str::from_utf8(manifest.bytes())
        .unwrap_or_else(|_| fail("snapshot manifest is not UTF-8"));
    if text.is_empty() || !text.ends_with('\n') {
        fail("snapshot manifest is empty or unterminated");
    }
    let source = PinnedDirectory::open(Path::new(source_root))
        .unwrap_or_else(|_| fail("snapshot source root pinning refused"));
    let mut directories = BTreeSet::from([destination_root.to_owned()]);
    let mut bindings = Vec::new();
    let mut previous = "";
    let mut total = 0u64;
    for line in text.lines() {
        let mut fields = line.splitn(3, ' ');
        let digest = fields.next().unwrap_or("");
        let size_text = fields.next().unwrap_or("");
        let relative = fields.next().unwrap_or("");
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || size_text.is_empty()
            || (size_text.starts_with('0') && size_text != "0")
            || relative.is_empty()
            || relative.contains(' ')
            || relative <= previous
        {
            fail("snapshot manifest row is noncanonical");
        }
        let size = size_text
            .parse::<u64>()
            .unwrap_or_else(|_| fail("snapshot manifest size is malformed"));
        total = total
            .checked_add(size)
            .filter(|value| *value <= total_maximum)
            .unwrap_or_else(|| fail("snapshot manifest aggregate exceeds its ceiling"));
        let capture = source
            .capture_regular_file(relative, size)
            .unwrap_or_else(|error| fail(&format!("snapshot member capture refused for {relative}: {error}")));
        if capture.bytes().len() as u64 != size || sha256_hex(capture.bytes()) != digest {
            fail("snapshot member bytes disagree with the authenticated manifest");
        }
        *sequence += 1;
        let file_is_executable = executable
            && matches!(relative, "bin/cargo" | "bin/rustc" | "bin/rustdoc")
            || executable && relative.ends_with("/bin/rust-lld");
        let name = format!("keep-snapshot-{sequence}");
        let sealed = if file_is_executable {
            seal_file_bytes(&name, capture.bytes(), size, 0o500)
        } else {
            seal_data_file_bytes(&name, capture.bytes(), size, 0o400)
        }
        .unwrap_or_else(|error| {
            fail(&format!(
                "snapshot member sealing refused for {relative}: {error}"
            ))
        });
        let descriptor = sealed
            .make_inheritable()
            .unwrap_or_else(|_| fail("snapshot descriptor inheritance refused"));
        let destination = format!("{destination_root}/{relative}");
        let mut parent = Path::new(&destination).parent();
        while let Some(path) = parent {
            let value = path.to_string_lossy().into_owned();
            if value.len() < destination_root.len() {
                break;
            }
            directories.insert(value);
            parent = path.parent();
        }
        bindings.extend([
            "--perms".to_owned(),
            if file_is_executable { "0500" } else { "0400" }.to_owned(),
            "--ro-bind-data".to_owned(),
            descriptor.to_string(),
            destination,
        ]);
        sealed_files.push(sealed);
        previous = relative;
    }
    let mut arguments = Vec::new();
    for directory in directories {
        arguments.extend(["--dir".to_owned(), directory]);
    }
    arguments.extend(bindings);
    arguments
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let unit = arguments
        .next()
        .unwrap_or_else(|| fail("cgroup unit argument is missing"));
    let work = arguments
        .next()
        .unwrap_or_else(|| fail("work root is missing"));
    let toolchain = arguments
        .next()
        .unwrap_or_else(|| fail("toolchain root is missing"));
    let toolchain_manifest = arguments
        .next()
        .unwrap_or_else(|| fail("toolchain manifest is missing"));
    let toolchain_manifest_digest = arguments
        .next()
        .unwrap_or_else(|| fail("toolchain manifest digest is missing"));
    let build_cell = arguments
        .next()
        .unwrap_or_else(|| fail("build-cell path is missing"));
    let vendor = arguments
        .next()
        .unwrap_or_else(|| fail("vendor root is missing"));
    let vendor_manifest = arguments
        .next()
        .unwrap_or_else(|| fail("vendor manifest is missing"));
    let vendor_manifest_digest = arguments
        .next()
        .unwrap_or_else(|| fail("vendor manifest digest is missing"));
    let result = arguments
        .next()
        .unwrap_or_else(|| fail("result root is missing"));
    let result_manifest = arguments
        .next()
        .unwrap_or_else(|| fail("result manifest is missing"));
    let result_manifest_digest = arguments
        .next()
        .unwrap_or_else(|| fail("result manifest digest is missing"));
    let operation = arguments
        .next()
        .unwrap_or_else(|| fail("closed operation is missing"));
    if arguments.next().is_some() {
        fail("extra supervisor arguments are forbidden");
    }
    let (program, program_arguments): (&str, Vec<&str>) = match operation.as_str() {
        "probe-namespace" => (
            "/bin/sh",
            vec![
                "-c",
                "test ! -e /root; test ! -e /outside; ! touch /outside 2>/dev/null; test \"$(wc -l < /proc/net/route)\" -eq 1; readlink /proc/self/ns/net",
            ],
        ),
        "metadata-unlocked" | "metadata-locked" | "check" | "probe-network" => {
            ("/keep/build-cell", vec![operation.as_str()])
        }
        "probe-snapshot-race" => ("/keep/build-cell", vec!["check"]),
        _ => fail("operation is outside the closed supervisor set"),
    };
    let mut bwrap_arguments = [
        "bwrap",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--dir",
        "/keep",
        "--ro-bind",
        "/keep/build-cell-placeholder",
        "/keep/build-cell",
        "--bind",
        "/keep/work-placeholder",
        "/work",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let build_source_index = bwrap_arguments
        .iter()
        .position(|value| value == "/keep/build-cell-placeholder")
        .unwrap_or_else(|| fail("sandbox build placeholder is absent"));
    bwrap_arguments[build_source_index] = build_cell.clone();
    let work_source_index = bwrap_arguments
        .iter()
        .position(|value| value == "/keep/work-placeholder")
        .unwrap_or_else(|| fail("sandbox work placeholder is absent"));
    bwrap_arguments[work_source_index] = work.clone();
    let mut sealed_snapshot_files = Vec::new();
    let mut snapshot_sequence = 0usize;
    for arguments in [
        sealed_snapshot_arguments(
            &toolchain,
            &toolchain_manifest,
            &toolchain_manifest_digest,
            "/keep/toolchain",
            true,
            1024 * 1024 * 1024,
            &mut snapshot_sequence,
            &mut sealed_snapshot_files,
        ),
        sealed_snapshot_arguments(
            &vendor,
            &vendor_manifest,
            &vendor_manifest_digest,
            "/keep/vendor",
            false,
            64 * 1024 * 1024,
            &mut snapshot_sequence,
            &mut sealed_snapshot_files,
        ),
        sealed_snapshot_arguments(
            &result,
            &result_manifest,
            &result_manifest_digest,
            "/keep/result",
            false,
            64 * 1024 * 1024,
            &mut snapshot_sequence,
            &mut sealed_snapshot_files,
        ),
    ] {
        bwrap_arguments.extend(arguments);
    }
    if operation == "probe-snapshot-race" {
        let ready = Path::new(&work).join(".keep-snapshot-ready");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&ready)
            .unwrap_or_else(|_| fail("snapshot-race readiness creation refused"));
        let mutated = Path::new(&work).join(".keep-snapshot-mutated");
        for _ in 0..500 {
            if mutated.is_file() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !mutated.is_file() {
            fail("snapshot-race mutation acknowledgement timed out");
        }
    }
    bwrap_arguments.extend([
        "--clearenv".to_owned(),
        "--setenv".to_owned(),
        "PATH".to_owned(),
        "/keep/toolchain/bin:/usr/bin:/bin".to_owned(),
        "--setenv".to_owned(),
        "HOME".to_owned(),
        "/work/.home".to_owned(),
        "--setenv".to_owned(),
        "LANG".to_owned(),
        "C".to_owned(),
        "--setenv".to_owned(),
        "LC_ALL".to_owned(),
        "C".to_owned(),
        "--setenv".to_owned(),
        "TZ".to_owned(),
        "UTC".to_owned(),
        "--setenv".to_owned(),
        "SOURCE_DATE_EPOCH".to_owned(),
        "0".to_owned(),
        "--setenv".to_owned(),
        "RUSTUP_TOOLCHAIN".to_owned(),
        "1.97.1-x86_64-unknown-linux-gnu".to_owned(),
        "--setenv".to_owned(),
        "CARGO_HOME".to_owned(),
        "/work/.cargo-home".to_owned(),
        "--setenv".to_owned(),
        "CARGO_NET_OFFLINE".to_owned(),
        "true".to_owned(),
        "--setenv".to_owned(),
        "CARGO_INCREMENTAL".to_owned(),
        "0".to_owned(),
        "--setenv".to_owned(),
        "CARGO_TARGET_DIR".to_owned(),
        "/work/target".to_owned(),
        "--setenv".to_owned(),
        "RUSTC".to_owned(),
        "/keep/toolchain/bin/rustc".to_owned(),
        "--setenv".to_owned(),
        "RUSTDOC".to_owned(),
        "/keep/toolchain/bin/rustdoc".to_owned(),
        "--setenv".to_owned(),
        "RUSTFLAGS".to_owned(),
        "--cfg=curve25519_dalek_backend=\"fiat\" --cfg=curve25519_dalek_bits=\"64\"".to_owned(),
        "--cap-drop".to_owned(),
        "ALL".to_owned(),
        "--chdir".to_owned(),
        "/work".to_owned(),
        program.to_owned(),
    ]);
    bwrap_arguments.extend(program_arguments.into_iter().map(str::to_owned));
    verify_cgroup(&unit, Path::new(&work));
    let mut pinned_directories = Vec::new();
    let mut pinned_files: Vec<SealedExecutable> = Vec::new();
    let mut build_cell_binding_index = None;
    let mut index = 1usize;
    let mut observed_destinations = Vec::new();
    while index < bwrap_arguments.len() {
        let binding = bwrap_arguments[index].as_str();
        if binding != "--ro-bind" && binding != "--bind" {
            index += 1;
            continue;
        }
        if index + 2 >= bwrap_arguments.len() {
            fail("bubblewrap binding is truncated");
        }
        let source = bwrap_arguments[index + 1].clone();
        let destination = bwrap_arguments[index + 2].clone();
        let expected_mode = match destination.as_str() {
            "/work" => "--bind",
            "/usr" | "/keep/toolchain" | "/keep/vendor" | "/keep/result" => "--ro-bind",
            "/keep/build-cell" => "--ro-bind",
            _ => fail("bubblewrap binding destination is outside the closed set"),
        };
        if binding != expected_mode || observed_destinations.contains(&destination) {
            fail("bubblewrap binding mode or destination uniqueness disagreed");
        }
        observed_destinations.push(destination.clone());
        let descriptor = if destination == "/keep/build-cell" {
            let source_path = Path::new(&source);
            let parent = PinnedDirectory::open(
                source_path
                    .parent()
                    .unwrap_or_else(|| fail("build-cell parent is absent")),
            )
            .unwrap_or_else(|_| fail("build-cell parent pinning refused"));
            let capture = parent
                .capture_regular_file(
                    source_path
                        .file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or_else(|| fail("build-cell leaf is malformed")),
                    4 * 1024 * 1024,
                )
                .unwrap_or_else(|_| fail("build-cell capture refused"));
            let sealed =
                seal_executable_bytes("keep-objective3-cell", capture.bytes(), 4 * 1024 * 1024)
                    .unwrap_or_else(|_| fail("build-cell sealing refused"));
            let descriptor = sealed
                .make_inheritable()
                .unwrap_or_else(|_| fail("build-cell descriptor inheritance refused"));
            pinned_files.push(sealed);
            descriptor
        } else {
            let pinned = PinnedDirectory::open(Path::new(&source))
                .unwrap_or_else(|_| fail("bind-source pinning refused"));
            let descriptor = pinned
                .make_inheritable()
                .unwrap_or_else(|_| fail("bind-source descriptor inheritance refused"));
            pinned_directories.push(pinned);
            descriptor
        };
        // Bubblewrap closes unrelated inherited descriptors before resolving pathname binds.
        // Its fd-bind interface both preserves the descriptor and mounts that exact open object.
        bwrap_arguments[index] = if binding == "--bind" {
            "--bind-fd".to_owned()
        } else if destination == "/keep/build-cell" {
            build_cell_binding_index = Some(index);
            "--ro-bind-data".to_owned()
        } else {
            "--ro-bind-fd".to_owned()
        };
        bwrap_arguments[index + 1] = descriptor.to_string();
        index += 3;
    }
    if observed_destinations.len() != 3 {
        fail("bubblewrap binding set is incomplete");
    }
    let build_cell_binding_index =
        build_cell_binding_index.unwrap_or_else(|| fail("build-cell binding is absent"));
    bwrap_arguments.splice(
        build_cell_binding_index..build_cell_binding_index,
        ["--perms".to_owned(), "0500".to_owned()],
    );
    let binaries = PinnedDirectory::open(Path::new("/usr/bin"))
        .unwrap_or_else(|_| fail("/usr/bin pinning refused"));
    let capture = binaries
        .capture_regular_file("bwrap", 4 * 1024 * 1024)
        .unwrap_or_else(|_| fail("bubblewrap capture refused"));
    if sha256_hex(capture.bytes()) != BWRAP_DIGEST {
        fail("bubblewrap bytes differ from the frozen identity");
    }
    let sealed = seal_executable_bytes("keep-objective3-bwrap", capture.bytes(), 4 * 1024 * 1024)
        .unwrap_or_else(|_| fail("bubblewrap sealing refused"));
    let argv = bwrap_arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    // These descriptors are the bind-source identities consumed by bubblewrap after exec.
    // Successful exec replaces this process; failed exec exits immediately below, so keeping
    // them open for the remainder of this process is both intentional and bounded.
    std::mem::forget(pinned_directories);
    std::mem::forget(pinned_files);
    std::mem::forget(sealed_snapshot_files);
    let error = sealed.exec(
        &argv,
        &[
            ("PATH", "/usr/bin:/bin"),
            ("LANG", "C"),
            ("LC_ALL", "C"),
            ("TZ", "UTC"),
        ],
    );
    fail(&format!("sealed bubblewrap exec failed: {error}"));
}
