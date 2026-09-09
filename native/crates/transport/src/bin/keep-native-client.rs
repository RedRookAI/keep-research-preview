#![forbid(unsafe_code)]

#[cfg(debug_assertions)]
use keep_native_transport::sha256_file_bounded;
use keep_native_transport::{exchange_refusal, read_framed, write_framed};
#[cfg(not(debug_assertions))]
use nix::fcntl::{OFlag, openat};
#[cfg(not(debug_assertions))]
use nix::sys::stat::Mode;
#[cfg(not(debug_assertions))]
use std::fs::{self, File, OpenOptions};
#[cfg(not(debug_assertions))]
use std::io::Read;
#[cfg(not(debug_assertions))]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

fn argument(name: &str) -> Result<String, String> {
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == name {
            return arguments
                .next()
                .ok_or_else(|| format!("missing value for {name}"));
        }
    }
    Err(format!("missing argument {name}"))
}

#[cfg(not(debug_assertions))]
fn packaged_supervisor_digest(package: &std::path::Path) -> Result<(String, u64), String> {
    if fs::canonicalize(package).map_err(|error| format!("canonicalize package: {error}"))?
        != package
    {
        return Err("client package directory is not canonical".to_owned());
    }
    let directory_file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(package)
        .map_err(|error| format!("open client package directory: {error}"))?;
    let directory = directory_file
        .metadata()
        .map_err(|error| format!("client package directory metadata: {error}"))?;
    if !directory.is_dir()
        || directory.uid() != 0
        || directory.gid() != 0
        || directory.mode() & 0o777 != 0o555
    {
        return Err("client package directory ownership or mode is invalid".to_owned());
    }
    for ancestor in package.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|error| format!("client package ancestor metadata: {error}"))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err("client package ancestor ownership or mode is invalid".to_owned());
        }
    }
    let mut file = File::from(
        openat(
            &directory_file,
            "keep-native-supervisor.sha256",
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| format!("open packaged supervisor digest: {error}"))?,
    );
    let before = file
        .metadata()
        .map_err(|error| format!("packaged supervisor digest metadata: {error}"))?;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.mode() & 0o777 != 0o444
        || before.len() != 65
    {
        return Err("packaged supervisor digest ownership, mode, or size is invalid".to_owned());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(66)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read packaged supervisor digest: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("recapture packaged supervisor digest metadata: {error}"))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || bytes.len() != 65
        || bytes[64] != b'\n'
    {
        return Err("packaged supervisor digest changed during capture".to_owned());
    }
    let digest = std::str::from_utf8(&bytes[..64])
        .map_err(|_| "packaged supervisor digest is not UTF-8")?
        .to_owned();
    if !digest
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("packaged supervisor digest is malformed".to_owned());
    }
    Ok((digest, directory.dev()))
}

fn main() {
    let result = (|| {
        let socket = PathBuf::from(argument("--socket")?);
        let uid = argument("--expected-server-uid")?
            .parse::<u32>()
            .map_err(|_| "invalid expected server uid".to_owned())?;
        let gid = argument("--expected-server-gid")?
            .parse::<u32>()
            .map_err(|_| "invalid expected server gid".to_owned())?;
        let security_label = argument("--expected-server-security-label")?;
        let executable =
            std::env::current_exe().map_err(|error| format!("current executable: {error}"))?;
        let package = executable
            .parent()
            .ok_or("client executable has no package directory")?;
        #[cfg(debug_assertions)]
        let supervisor_digest = sha256_file_bounded(&package.join("keep-native-supervisor"))?;
        #[cfg(debug_assertions)]
        let supervisor_device = None;
        #[cfg(not(debug_assertions))]
        let (supervisor_digest, package_device) = packaged_supervisor_digest(package)?;
        #[cfg(not(debug_assertions))]
        let supervisor_device = Some(package_device);
        let request = read_framed(std::io::stdin().lock())?;
        let response = exchange_refusal(
            &socket,
            uid,
            gid,
            security_label.as_ref(),
            &supervisor_digest,
            supervisor_device,
            &request,
        )?;
        write_framed(std::io::stdout().lock(), &response)
    })();
    if let Err(error) = result {
        eprintln!("keep-native-client: {error}");
        std::process::exit(1);
    }
}
