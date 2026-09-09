#![forbid(unsafe_code)]

use keep_native_prober_launcher::candidate_probe::{
    construct_authenticated_fixture, enroll_repository_fixture, exercise_bounded_host_fixture,
    exercise_cgroup_v2_fixture, exercise_guest_output_overflow, exercise_launch_input_substitution,
    exercise_malformed_shim_handoff, exercise_seccomp_denial_canary,
    exercise_wrong_authentication_timeout, exercise_zero_guest_network_devices,
    launch_authenticated_fixture,
};

fn main() {
    let enrollment = enroll_repository_fixture();
    if std::env::args_os().skip(1).eq(["--seccomp-canary-only"]) {
        match exercise_seccomp_denial_canary(&enrollment) {
            Ok(()) => {
                eprintln!(
                    "HOSTILE_OK\tmeasured seccomp denial policy trapped SIGSYS and cleaned without residue"
                );
                return;
            }
            Err(error) => {
                eprintln!("REFUSED\tnative PROBER hostile seccomp canary failed: {error}");
                std::process::exit(2);
            }
        }
    }
    if let Err(error) = exercise_bounded_host_fixture(&enrollment) {
        eprintln!("REFUSED\tnative PROBER launch-candidate fixture failed: {error}");
        std::process::exit(2);
    }
    if let Err(error) = exercise_cgroup_v2_fixture(&enrollment) {
        eprintln!("REFUSED\tnative PROBER launch-candidate cgroup fixture failed: {error}");
        std::process::exit(2);
    }
    match construct_authenticated_fixture(&enrollment) {
        Ok(fixture) => {
            match launch_authenticated_fixture(&enrollment, &fixture) {
                Ok(observation) => eprintln!(
                    "CANDIDATE_OK\texit={} jailer={} landlockAbi={} landlockWriteDenied={} landlockCreateDenied={} seccomp={} seccompPolicy={} seccompThreads={} seccompFilters={} capsEmpty={} socketsAbsent={} envEmpty={} inheritedFdAbsent={} pidns={} mntns={} chroot={} memory={} pids={} stdout={}",
                    observation.guest.exit_code,
                    observation.jailer_exit_success,
                    observation.landlock.abi,
                    observation.landlock.denied_write_errno == 13,
                    observation.landlock.denied_create_errno == 13,
                    observation.containment.seccomp_mode,
                    observation.seccomp.compiled_policy_sha256,
                    observation.seccomp.live_thread_count,
                    observation.seccomp.filters_per_thread,
                    observation.containment.capabilities_empty,
                    observation.containment.socket_descriptors_absent,
                    observation.containment.environment_empty,
                    observation.containment.inherited_descriptor_absent,
                    observation.containment.pid_namespace_isolated,
                    observation.containment.mount_namespace_isolated,
                    observation.containment.chroot_matches_jail,
                    observation.cgroup.memory_max,
                    observation.cgroup.pids_max,
                    observation.guest.stdout.trim_end()
                ),
                Err(error) => {
                    eprintln!("REFUSED\tnative PROBER launch-candidate VM failed: {error}");
                    drop(fixture);
                    std::process::exit(2);
                }
            }
            drop(fixture);
        }
        Err(error) => {
            eprintln!("REFUSED\tnative PROBER launch-candidate image fixture failed: {error}");
            std::process::exit(2);
        }
    }
    if let Err(error) = exercise_launch_input_substitution(&enrollment) {
        eprintln!("REFUSED\tnative PROBER hostile substitution probe failed: {error}");
        std::process::exit(2);
    }
    eprintln!("HOSTILE_OK\tpost-construction launch input substitution refused without residue");
    if let Err(error) = exercise_malformed_shim_handoff(&enrollment) {
        eprintln!("REFUSED\tnative PROBER hostile Landlock handoff probe failed: {error}");
        std::process::exit(2);
    }
    eprintln!("HOSTILE_OK\tmalformed post-jailer handoff refused before VMM exec without residue");
    if let Err(error) = exercise_seccomp_denial_canary(&enrollment) {
        eprintln!("REFUSED\tnative PROBER hostile seccomp canary failed: {error}");
        std::process::exit(2);
    }
    eprintln!(
        "HOSTILE_OK\tmeasured seccomp denial policy trapped SIGSYS and cleaned without residue"
    );
    if let Err(error) = exercise_wrong_authentication_timeout(&enrollment) {
        eprintln!("REFUSED\tnative PROBER hostile authentication probe failed: {error}");
        std::process::exit(2);
    }
    eprintln!("HOSTILE_OK\twrong authenticated frame rejected and cleaned without residue");
    if let Err(error) = exercise_guest_output_overflow(&enrollment) {
        eprintln!("REFUSED\tnative PROBER hostile output probe failed: {error}");
        std::process::exit(2);
    }
    eprintln!("HOSTILE_OK\tguest output overflow bounded and cleaned without residue");
    if let Err(error) = exercise_zero_guest_network_devices(&enrollment) {
        eprintln!("REFUSED\tnative PROBER hostile network probe failed: {error}");
        std::process::exit(2);
    }
    eprintln!("HOSTILE_OK\tguest has only loopback and live VMM has no socket descriptors");
    eprintln!("REFUSED\tnative PROBER launch candidate has no production authority join");
    std::process::exit(2);
}
