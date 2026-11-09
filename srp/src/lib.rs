#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "getrandom", doc = include_str!("../README.md"))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(clippy::many_single_char_names)]
#![forbid(unsafe_code)]
#![warn(
    clippy::checked_conversions,
    clippy::integer_division_remainder_used,
    clippy::mod_module_files,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::unwrap_used,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_lifetimes,
    unused_qualifications
)]

//! # Usage
//! See [`Client`] and [`Server`] types for usage information.
//!
//! # Algorithm description
//! The non-deprecated `process_reply` methods implement the following SRP-6a
//! exchange. Group arithmetic is modulo the safe prime `N = 2q + 1`, where `q`
//! is prime. Hash outputs are interpreted as unsigned big-endian integers when
//! used in arithmetic; exponent arithmetic is not reduced modulo `N`.
//!
//! Additionally, `g` MUST be a generator modulo `N`. It's STRONGLY recommended to use SRP
//! parameters provided by this crate under the [`groups`] module, and available as various
//! type aliases e.g. [`ClientG2048`] and [`ServerG2048`].
//!
//! | Client | Data transfer | Server |
//! | --- | --- | --- |
//! | `A = g^a mod N` | — `I`, `A` → | Look up `s`, `v` for `I` |
//! | `x = H(s ‖ H(I ‖ ":" ‖ P))` | ← `s`, `B` — | `B = (k*v + g^b) mod N` |
//! | `u = H(PAD(A) ‖ PAD(B))` | | `u = H(PAD(A) ‖ PAD(B))` |
//! | `S = (B - k*g^x)^(a + u*x) mod N` | | `S = (A*v^u)^b mod N` |
//! | `K = H(MIN(S))` | | `K = H(MIN(S))` |
//! | Compute `M1` | — `M1` → | Verify `M1` before sending `M2` |
//! | Verify `M2` | ← `M2` — | `M2 = H(A ‖ M1 ‖ K)` |
//!
//! By default, `M1 = H((H(N) XOR H(PAD(g))) ‖ H(I) ‖ s ‖ A ‖ B ‖ K)`.
//! Setting [`EncodingOptions::m1_generator`] to [`IntegerEncoding::Minimal`]
//! uses `H(MIN(g))` in this proof; it does not change `k`.
//! Setting [`EncodingOptions::username_in_x`] to `false` omits `I` only from
//! the inner hash used to compute `x`.
//!
//! For `u`, both public values are padded internally. In the default proofs,
//! public values are minimally encoded, independently of their wire representation.
//! [`Client::new_with_options`] and [`Server::new_with_options`] configure password
//! derivation and integer encodings via [`EncodingOptions`].
//!
//! [`ClientVerifier::key`] and [`ServerVerifier::key`] return `MIN(S)`, without
//! authenticating the peer. Successful [`ClientVerifier::verify_server`] or
//! [`ServerVerifier::verify_client`] returns the session key `K`.
//!
//! Variables and notations have the following meaning:
//!
//! - `I` — user identity (username)
//! - `P` — user password
//! - `H` — one-way hash function
//! - `PAD` — unsigned big-endian encoding, left-padded to the byte length of `N`
//! - `MIN` — unsigned big-endian encoding with leading zero bytes removed
//! - `^` — exponentiation
//! - `‖` — concatenation
//! - `x` — user private key
//! - `s` — random salt stored with the verifier on the server
//! - `v` — password verifier equal to `g^x mod N` and stored on the server
//! - `a`, `b` — secret ephemeral values (at least 256 bits in length)
//! - `A`, `B` — Public ephemeral values
//! - `u` — scrambling parameter
//! - `k` — multiplier parameter, `k = H(N ‖ PAD(g))`

#[macro_use]
extern crate alloc;

pub mod groups;
#[doc(hidden)]
pub mod utils;

mod client;
mod encoding;
mod errors;
mod server;

pub use bigint;
pub use client::{Client, ClientG2048, ClientG3072, ClientG4096, ClientVerifier};
pub use common;
pub use encoding::{EncodingOptions, IntegerEncoding};
pub use errors::AuthError;
pub use groups::Group;
pub use server::{Server, ServerG2048, ServerG3072, ServerG4096, ServerVerifier};

#[allow(deprecated)]
pub use {
    client::{ClientG1024, ClientG1536, LegacyClientVerifier},
    server::{LegacyServerVerifier, ServerG1024, ServerG1536},
};

#[cfg(feature = "rand_core")]
pub use common::Generate;
#[cfg(feature = "rand_core")]
pub use common::rand_core;

/// 384-bit ephemeral secret (usable as `a` or `b`).
///
/// Should be large enough for use with any of the groups defined in this crate.
pub type EphemeralSecret = [u8; 48];

/// 128-bit (16-byte) salt value.
///
/// An opaque byte string: retain all bytes, including leading zeros, when
/// storing, transmitting, or hashing it.
pub type Salt = [u8; 16];
