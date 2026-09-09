#![forbid(unsafe_code)]

use keep_native_linux_abi::LandlockRuleset;
use keep_native_prober_vmm_shim::{
    ACTUAL_VMM_PATH, CREATED_CANARY_PATH, DENIED_CANARY_PATH, HandoffMode, KVM_PATH, MARKER_PREFIX,
    PROJECT_PATH, SECCOMP_MARKER_PREFIX, validate_jailer_handoff,
};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

fn fail(message: &str) -> ! {
    eprintln!("{MARKER_PREFIX} REFUSED {message}");
    std::process::exit(125)
}

fn exact_denial(result: io::Result<File>, message: &str) {
    match result {
        Err(error) if error.raw_os_error() == Some(13) => {}
        Ok(_) => fail(message),
        Err(_) => fail("Landlock canary returned the wrong error class"),
    }
}

fn main() {
    if std::env::vars_os().next().is_some() {
        fail("jailer environment was not empty");
    }
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let mode = validate_jailer_handoff(&arguments).unwrap_or_else(|message| fail(message));

    let root = File::open("/").unwrap_or_else(|_| fail("private jail root was not readable"));
    let project = OpenOptions::new()
        .read(true)
        .write(true)
        .open(PROJECT_PATH)
        .unwrap_or_else(|_| fail("writable project image was not available"));
    let kvm = OpenOptions::new()
        .read(true)
        .write(true)
        .open(KVM_PATH)
        .unwrap_or_else(|_| fail("private KVM device was not available"));
    let canary = OpenOptions::new()
        .read(true)
        .write(true)
        .open(DENIED_CANARY_PATH)
        .unwrap_or_else(|_| fail("pre-Landlock writable canary was not writable"));
    drop(canary);

    let ruleset =
        LandlockRuleset::new(4).unwrap_or_else(|_| fail("reviewed Landlock ABI was not available"));
    ruleset
        .allow_read_only(&root)
        .unwrap_or_else(|_| fail("read-only jail rule was refused"));
    ruleset
        .allow_read_write_file(&project)
        .unwrap_or_else(|_| fail("project-image write rule was refused"));
    ruleset
        .allow_device(&kvm)
        .unwrap_or_else(|_| fail("KVM-device rule was refused"));
    let observation = ruleset.observation();
    let restricted_abi = ruleset
        .restrict_self()
        .unwrap_or_else(|_| fail("Landlock activation was refused"));

    exact_denial(
        OpenOptions::new().write(true).open(DENIED_CANARY_PATH),
        "Landlock admitted a forbidden existing-file write",
    );
    exact_denial(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(CREATED_CANARY_PATH),
        "Landlock admitted a forbidden file creation",
    );
    eprintln!(
        "{MARKER_PREFIX} abi={restricted_abi} fs={:x} net={:x} scoped={:x} deniedWrite=13 deniedCreate=13",
        observation.handled_filesystem, observation.handled_network, observation.scoped
    );

    drop(root);
    drop(project);
    drop(kvm);
    if mode == HandoffMode::SeccompCanary {
        use std::os::unix::process::ExitStatusExt as _;
        let status = Command::new(ACTUAL_VMM_PATH)
            .args(&arguments[..13])
            .current_dir("/")
            .env_clear()
            .status()
            .unwrap_or_else(|_| fail("measured seccomp-canary VMM spawn failed"));
        match status.signal() {
            Some(31) => {
                eprintln!("{SECCOMP_MARKER_PREFIX} signal=31");
                std::process::exit(125);
            }
            _ => fail("measured seccomp-canary VMM did not terminate with SIGSYS"),
        }
    }
    let error = Command::new(ACTUAL_VMM_PATH)
        .args(&arguments)
        .current_dir("/")
        .env_clear()
        .exec();
    fail(&format!("measured VMM exec failed: {error}"));
}
