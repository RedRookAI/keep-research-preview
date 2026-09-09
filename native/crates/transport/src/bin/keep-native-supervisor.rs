#![forbid(unsafe_code)]

use keep_native_transport::serve_one_refusal;
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

fn main() {
    let result = (|| {
        let socket = PathBuf::from(argument("--socket")?);
        let uid = argument("--expected-client-uid")?
            .parse::<u32>()
            .map_err(|_| "invalid expected client uid".to_owned())?;
        let gid = argument("--expected-client-gid")?
            .parse::<u32>()
            .map_err(|_| "invalid expected client gid".to_owned())?;
        let security_label = argument("--expected-client-security-label")?;
        serve_one_refusal(&socket, uid, gid, security_label.as_ref())
    })();
    if let Err(error) = result {
        eprintln!("keep-native-supervisor: {error}");
        std::process::exit(1);
    }
}
