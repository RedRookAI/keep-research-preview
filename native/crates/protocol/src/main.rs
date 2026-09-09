#![forbid(unsafe_code)]
use keep_native_protocol::p2_schema::{
    B3_OPERATION_SCHEMAS, P2_SCHEMAS, capture_p2, combined_digest_registry, minimal_p2_corpus,
    operation_digest, recursive_schema_metadata, signature_preimage, signature_preimage_registry,
};
use keep_native_protocol::{
    Limits, TrustClass, capture_canonical, decode_canonical, encode_bounded, sha256_hex,
};
use std::io::{self, BufRead};

fn decode_hex(text: &str) -> Result<Vec<u8>, &'static str> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex");
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| "invalid hex"))
        .collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let result = line.map_err(|_| "stdin").and_then(|line| {
            if line.trim() == "P2REGISTRY" {
                let rows = combined_digest_registry()
                    .into_iter()
                    .map(|entry| {
                        let mut dependencies = entry.depends_on.clone();
                        dependencies.sort();
                        format!(
                            "{}|{}|{}|{}",
                            entry.path,
                            entry.semantic_type,
                            entry.rank,
                            dependencies.join(",")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(";");
                return Ok(format!("P2REGISTRY\t{rows}"));
            }
            if line.trim() == "P2SCHEMAS" {
                let mut schemas = P2_SCHEMAS
                    .iter()
                    .chain(B3_OPERATION_SCHEMAS)
                    .collect::<Vec<_>>();
                schemas.sort_by_key(|schema| schema.name);
                let rows = schemas
                    .into_iter()
                    .map(|schema| {
                        let fields = schema
                            .fields
                            .iter()
                            .map(|field| field.name)
                            .collect::<Vec<_>>()
                            .join(",");
                        let domain = schema.signature_domain.map(hex).unwrap_or_default();
                        format!(
                            "{}|{}|{:?}|{}|{}|{}",
                            schema.name,
                            schema.schema,
                            schema.shape,
                            schema.maximum_bytes,
                            fields,
                            domain
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(";");
                return Ok(format!("P2SCHEMAS\t{rows}"));
            }
            if line.trim() == "P2SCHEMADETAIL" {
                return recursive_schema_metadata()
                    .map(|bytes| format!("P2SCHEMADETAIL\t{}", hex(&bytes)))
                    .map_err(|_| "recursive schema metadata");
            }
            if line.trim() == "P2SIGNATURES" {
                let rows = signature_preimage_registry()
                    .iter()
                    .map(|row| {
                        format!(
                            "{}|{}|{}",
                            row.schema_name,
                            hex(row.domain),
                            row.output_bytes
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(";");
                return Ok(format!("P2SIGNATURES\t{rows}"));
            }
            if line.trim() == "P2CORPUS" {
                let rows = minimal_p2_corpus()
                    .map_err(|error| error.0)?
                    .into_iter()
                    .map(|(name, bytes)| format!("{name}|{}", hex(&bytes)))
                    .collect::<Vec<_>>()
                    .join(";");
                return Ok(format!("P2CORPUS\t{rows}"));
            }
            if let Some(rest) = line.trim().strip_prefix("P2:") {
                let (schema, encoded) =
                    rest.split_once(':').ok_or("P2 mode requires schema:hex")?;
                let bytes = decode_hex(encoded)?;
                let captured = capture_p2(&bytes, Some(schema)).map_err(|error| error.0)?;
                return Ok(format!(
                    "P2\t{}\t{}\t{}",
                    captured.schema_name(),
                    sha256_hex(captured.canonical_bytes()),
                    hex(captured.canonical_bytes())
                ));
            }
            if let Some(rest) = line.trim().strip_prefix("P2OP:") {
                let (schema, encoded) = rest
                    .split_once(':')
                    .ok_or("P2OP mode requires schema:hex")?;
                let bytes = decode_hex(encoded)?;
                let value = decode_canonical(&bytes, Limits::MANIFEST).map_err(|error| error.0)?;
                let digest = operation_digest(schema, &value).map_err(|error| error.0)?;
                return Ok(format!("P2OP\t{schema}\t{digest}"));
            }
            if let Some(rest) = line.trim().strip_prefix("P2SIG:") {
                let (schema, encoded) = rest
                    .split_once(':')
                    .ok_or("P2SIG mode requires schema:hex")?;
                let bytes = decode_hex(encoded)?;
                let value = decode_canonical(&bytes, Limits::MANIFEST).map_err(|error| error.0)?;
                let preimage = signature_preimage(schema, &value).map_err(|error| error.0)?;
                return Ok(format!("P2SIG\t{schema}\t{}", hex(&preimage)));
            }
            if let Some(hex) = line.trim().strip_prefix("SHA:") {
                return decode_hex(hex).map(|bytes| format!("SHA\t{}", sha256_hex(&bytes)));
            }
            let (value_only, encoded) = line
                .trim()
                .strip_prefix("VALUE:")
                .map_or((false, line.trim()), |hex| (true, hex));
            let bytes = decode_hex(encoded)?;
            if !value_only {
                let captured = capture_canonical(&bytes, Limits::EVIDENCE, TrustClass::Development)
                    .map_err(|error| error.0)?;
                return Ok(format!(
                    "OK\t{:?}\t{}\t{}",
                    captured.schema(),
                    sha256_hex(captured.canonical_bytes()),
                    hex(captured.canonical_bytes())
                ));
            }
            let value = decode_canonical(&bytes, Limits::EVIDENCE).map_err(|error| error.0)?;
            let schema = "Value";
            let canonical = encode_bounded(&value, Limits::EVIDENCE).map_err(|error| error.0)?;
            Ok(format!(
                "OK\t{schema}\t{}\t{}",
                sha256_hex(&canonical),
                hex(&canonical)
            ))
        });
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => println!("ERR\t{error}"),
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
