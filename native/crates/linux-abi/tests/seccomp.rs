#![forbid(unsafe_code)]

use keep_native_linux_abi::{install_objective3_seccomp_filter, no_new_privileges_active};
use std::process::Command;

const CHILD_ENV: &str = "KEEP_LINUX_ABI_SECCOMP_CHILD";

#[test]
fn seccomp_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    install_objective3_seccomp_filter().unwrap();
    assert!(no_new_privileges_active().unwrap());
    assert!(std::fs::read("/proc/self/status").is_ok());
    let status = Command::new("/usr/bin/unshare")
        .arg("--mount")
        .arg("true")
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn seccomp_denies_namespace_creation_but_retains_declared_process_work() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "seccomp_child", "--nocapture"])
        .env(CHILD_ENV, "1")
        .status()
        .unwrap();
    assert!(status.success());
}
