#![forbid(unsafe_code)]

//! Public P2-D2 evidence facade. The single pure implementation lives beside the
//! native protocol codecs so filesystem consumers can reuse it without another
//! dependency edge. This crate retains its API and has no effect authority.

pub mod audit_plan;
pub use keep_native_protocol::p2_d2::*;
