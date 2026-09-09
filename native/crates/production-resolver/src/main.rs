#![forbid(unsafe_code)]

use keep_native_production_resolver::{
    ConfiguredRoot, ConfiguredRootIdentity, ProductionResolver, ResolverConfiguration,
    enroll_configured_root_for_probe,
};
use std::path::Path;

fn main() {
    if let Err(error) = run() {
        eprintln!("REFUSED\t{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() == 3 && arguments[1] == "--observe-root" {
        let root = enroll_configured_root_for_probe(Path::new(&arguments[2]))?;
        println!("ROOT\t{}", root.identity().decimal_spec());
        return Ok(());
    }
    if arguments.len() != 7 {
        return Err("expected authority-root authority-identity payload-root payload-identity deployment-id manifest-digest".into());
    }
    let authority = ConfiguredRoot::open(
        Path::new(&arguments[1]),
        ConfiguredRootIdentity::parse_decimal_spec(&arguments[2])?,
    )?;
    let payload = ConfiguredRoot::open(
        Path::new(&arguments[3]),
        ConfiguredRootIdentity::parse_decimal_spec(&arguments[4])?,
    )?;
    let resolver = ProductionResolver::open(ResolverConfiguration::new(authority, payload)?)?;
    let observation = resolver.observe_deployment(&arguments[5], &arguments[6])?;
    let artifacts = observation
        .artifact_identities()
        .map(|(id, kind, digest, length)| format!("{}:{}:{digest}:{length}", hex(id), hex(kind)))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "OBSERVED\t{}\t{}\t{}\t{}\t{}",
        observation.deployment_id(),
        observation.manifest_digest(),
        observation.transcript_digest(),
        observation.sealed_byte_length(),
        artifacts,
    );
    Ok(())
}

fn hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
