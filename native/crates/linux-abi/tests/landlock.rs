#![forbid(unsafe_code)]

use keep_native_linux_abi::{LandlockRuleset, no_new_privileges_active};
use std::fs::{File, create_dir, read, write};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CHILD_ENV: &str = "KEEP_LINUX_ABI_LANDLOCK_CHILD";

fn scratch() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("keep-landlock-{}-{nonce}", std::process::id()));
    create_dir(&path).unwrap();
    path
}

#[test]
fn landlock_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let root = std::path::PathBuf::from(std::env::var_os("KEEP_LANDLOCK_ROOT").unwrap());
    let readable = File::open(root.join("readable")).unwrap();
    let writable = File::open(root.join("writable")).unwrap();
    let ruleset = LandlockRuleset::new(4).unwrap();
    ruleset.allow_read_only(&readable).unwrap();
    ruleset.allow_read_write(&writable).unwrap();
    assert!(ruleset.restrict_self().unwrap() >= 4);
    assert!(no_new_privileges_active().unwrap());
    assert_eq!(read(root.join("readable/input")).unwrap(), b"input\n");
    assert!(write(root.join("readable/denied"), b"no").is_err());
    write(root.join("writable/allowed"), b"yes").unwrap();
    assert!(read("/etc/passwd").is_err());
}

#[test]
fn landlock_denies_everything_except_exact_read_and_write_roots() {
    let root = scratch();
    create_dir(root.join("readable")).unwrap();
    create_dir(root.join("writable")).unwrap();
    write(root.join("readable/input"), b"input\n").unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "landlock_child", "--nocapture"])
        .env(CHILD_ENV, "1")
        .env("KEEP_LANDLOCK_ROOT", &root)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(read(root.join("writable/allowed")).unwrap(), b"yes");
    assert!(!root.join("readable/denied").exists());
    std::fs::remove_dir_all(root).unwrap();
}
