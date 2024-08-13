#![allow(clippy::many_single_char_names)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![doc = include_str!("../README.md")]

//! # Usage
//! Add `srp` dependency to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! srp = "0.6"
//! ```
//!
//! Next read documentation for [`client`](client/index.html) and
//! [`server`](server/index.html) modules.
//!
//! # Algorithm description
//! Here we briefly describe implemented algorithm. For additional information
//! refer to SRP literature. All arithmetic is done modulo `N`, where `N` is a
//! large safe prime (`N = 2q+1`, where `q` is prime). Additionally `g` MUST be
//! a generator modulo `N`. It's STRONGLY recommended to use SRP parameters
//! provided by this crate in the [`groups`](groups/index.html) module.
//!
//! |       Client           |   Data transfer   |      Server                     |
//! |------------------------|-------------------|---------------------------------|
//! |`a_pub = g^a`           | — `a_pub`, `I` —> | (lookup `s`, `v` for given `I`) |
//! |`x = PH(P, s)`          | <— `b_pub`, `s` — | `b_pub = k*v + g^b`             |
//! |`u = H(a_pub ‖ b_pub)`  |                   | `u = H(a_pub ‖ b_pub)`          |
//! |`S = (b_pub - k*g^x)^(a+u*x)` |             | `S = (b_pub - k*g^x)^(a+u*x)`   |
//! |`M1 = H(A ‖ B ‖ S)`     |     — `M1` —>     | (verify `M1`)                   |
//! |(verify `M2`)           |    <— `M2` —      | `M2 = H(A ‖ M1 ‖ S)`            |
//!
//! Variables and notations have the following meaning:
//!
//! - `I` — user identity (username)
//! - `P` — user password
//! - `H` — one-way hash function
//! - `PH` — password hashing algroithm, in the RFC 5054 described as
//! `H(s ‖ H(I ‖ ":" ‖ P))`
//! - `^` — (modular) exponentiation
//! - `‖` — concatenation
//! - `x` — user private key
//! - `s` — salt generated by user and stored on the server
//! - `v` — password verifier equal to `g^x` and stored on the server
//! - `a`, `b` — secret ephemeral values (at least 256 bits in length)
//! - `A`, `B` — Public ephemeral values
//! - `u` — scrambling parameter
//! - `k` — multiplier parameter (`k = H(N || g)` in SRP-6a)
//!
//! [1]: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
//! [2]: https://tools.ietf.org/html/rfc5054

pub mod client;
pub mod groups;
pub mod server;
pub mod types;
pub mod utils;
