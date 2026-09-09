#![forbid(unsafe_code)]

use keep_native_p2_d2_supervisor::capture_patch_inputs;
use keep_native_protocol::patch_capture::{
    CaptureError, MAX_CAPTURE_FRAME_BYTES, capture_input_request,
};
use std::io::{self, Read};

fn run() -> Result<(), CaptureError> {
    if std::env::args_os().len() != 1 {
        return Err(CaptureError::Malformed);
    }
    let mut input = io::stdin().lock();
    let mut length = [0u8; 4];
    input
        .read_exact(&mut length)
        .map_err(|_| CaptureError::Malformed)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(CaptureError::Malformed);
    }
    if length > MAX_CAPTURE_FRAME_BYTES {
        return Err(CaptureError::Limit);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| CaptureError::Limit)?;
    bytes.resize(length, 0);
    input
        .read_exact(&mut bytes)
        .map_err(|_| CaptureError::Malformed)?;
    if input.read(&mut [0u8; 1]).map_err(|_| CaptureError::Io)? != 0 {
        return Err(CaptureError::Malformed);
    }
    let request = capture_input_request(&bytes)?;
    let captured = capture_patch_inputs(request)?;
    let mut output = io::BufWriter::with_capacity(MAX_CAPTURE_FRAME_BYTES, io::stdout().lock());
    captured.write_response(&mut output)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{}", error.code());
        std::process::exit(2);
    }
}
