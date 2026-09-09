#![forbid(unsafe_code)]

//! Closed post-jailer handoff for the mechanically non-authorizing PROBER candidate.

pub const ACTUAL_VMM_PATH: &str = "/firecracker-vmm";
pub const CONFIG_PATH: &str = "/config.json";
pub const SECCOMP_FILTER_PATH: &str = "/seccomp.bpf";
pub const PROJECT_PATH: &str = "/project.ext4";
pub const KVM_PATH: &str = "/dev/kvm";
pub const DENIED_CANARY_PATH: &str = "/landlock-denied-canary";
pub const CREATED_CANARY_PATH: &str = "/landlock-created-canary";
pub const MARKER_PREFIX: &str = "[keep-prober-landlock]";
pub const SECCOMP_MARKER_PREFIX: &str = "[keep-prober-seccomp]";
pub const SECCOMP_CANARY_ARGUMENT: &str = "--keep-seccomp-canary";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffMode {
    Exec,
    SeccompCanary,
}

fn decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn attempt_id(value: &str) -> bool {
    value.len() == 37
        && value.starts_with("keep-")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn validate_jailer_handoff(arguments: &[String]) -> Result<HandoffMode, &'static str> {
    let mode = match arguments.len() {
        13 => HandoffMode::Exec,
        14 if arguments[13] == SECCOMP_CANARY_ARGUMENT => HandoffMode::SeccompCanary,
        _ => return Err("post-jailer VMM argument contract refused"),
    };
    if arguments.len() < 13
        || arguments[0] != "--id"
        || !attempt_id(&arguments[1])
        || arguments[2] != "--start-time-us"
        || !decimal(&arguments[3])
        || arguments[4] != "--start-time-cpu-us"
        || !decimal(&arguments[5])
        || arguments[6] != "--parent-cpu-time-us"
        || !decimal(&arguments[7])
        || arguments[8] != "--no-api"
        || arguments[9] != "--config-file"
        || arguments[10] != CONFIG_PATH
        || arguments[11] != "--seccomp-filter"
        || arguments[12] != SECCOMP_FILTER_PATH
    {
        return Err("post-jailer VMM argument contract refused");
    }
    Ok(mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Vec<String> {
        [
            "--id",
            "keep-0123456789abcdef0123456789abcdef",
            "--start-time-us",
            "1",
            "--start-time-cpu-us",
            "2",
            "--parent-cpu-time-us",
            "3",
            "--no-api",
            "--config-file",
            "/config.json",
            "--seccomp-filter",
            "/seccomp.bpf",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    #[test]
    fn handoff_is_exact_and_every_position_is_load_bearing() {
        let valid = valid();
        assert_eq!(validate_jailer_handoff(&valid).unwrap(), HandoffMode::Exec);
        for index in 0..valid.len() {
            let mut mutant = valid.clone();
            mutant[index].push('x');
            assert!(
                validate_jailer_handoff(&mutant).is_err(),
                "position {index}"
            );
        }
        assert!(validate_jailer_handoff(&valid[..12]).is_err());
        let mut extra = valid;
        extra.push("--api-sock".into());
        assert!(validate_jailer_handoff(&extra).is_err());
        extra[13] = SECCOMP_CANARY_ARGUMENT.into();
        assert_eq!(
            validate_jailer_handoff(&extra).unwrap(),
            HandoffMode::SeccompCanary
        );
    }
}
