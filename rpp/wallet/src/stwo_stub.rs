//! Minimal STWO compatibility shim compiled when the prover backend is disabled.
//! The wallet only requires the module namespace to exist so unit tests can link
//! against the mock prover implementation.

#![allow(dead_code)]

pub mod circuit {}
pub mod proof {}
pub mod prover {}
