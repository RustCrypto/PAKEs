# [RustCrypto]: Secure Remote Password

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [Secure Remote Password] password-authenticated
key exchange (PAKE) algorithm, using the **SRP-6a** construction.

Built on [`crypto-bigint`], a mathematical library designed for constant-time
operation.

## About

This implementation is generic over hash functions using the [`Digest`] trait,
so you will need to choose a hash function, e.g. `Sha256` from [`sha2`] crate.

The group parameters and SRP-6a computations follow [RFC5054], with the chosen
digest in place of SHA-1. This crate does not implement TLS-SRP: RFC 5054 uses
TLS Finished messages for authentication, not standalone SRP proofs.

The `process_reply` methods derive `K = H(S)` and prepare mutual authentication
proofs in the style of [RFC2945]. This is not the complete RFC 2945 protocol,
which uses an earlier SRP construction and SHA-1 interleaving to derive `K`.
Proof verification is a separate, required step before using the session key,
unless an enclosing protocol provides its own authentication. The lower-level
arithmetic methods are available for such protocols.

The deprecated `*_legacy` methods retain the `srp` 0.6-and-earlier construction:
unpadded inputs to `u` and proofs using the unhashed premaster secret `S`.

## HomeKit Usage

The following example generates a verifier and configures both SRP roles for
HomeKit Pair Setup:

```rust
use sha2::Sha512;
use srp::{ClientG3072, EncodingOptions, Generate, Salt, ServerG3072};

let username = b"Pair-Setup";
let setup_code = b"867-53-090"; // Example only: use accessory's setup code here
let salt = Salt::generate();
let client = ClientG3072::<Sha512>::new_with_options(EncodingOptions::HOMEKIT);
let v = client.compute_verifier(username, setup_code, &salt);
let server = ServerG3072::<Sha512>::new_with_options(EncodingOptions::HOMEKIT);
```

This preset matches Apple's [HomeKit ADK]. `Minimal` removes leading zero
bytes; `Padded` uses the modulus width (384 bytes for `G3072`). The SRP-6a
padding in `k` and `u` remains fixed. Salt bytes are always preserved. The
padded `A` in `M2` is an ADK convention, not a standalone-proof rule from RFC 5054.

After successful proof verification, `verify_client`/`verify_server` returns
`K`, which is the input to HomeKit's subsequent HKDF-SHA-512 derivations.
`key()` instead returns the unhashed `S` and must NOT be substituted for `K`.

## ⚠️ Security Warning

This crate has never received an independent third party audit for security and
correctness.

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

Rust **1.87** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/srp.svg
[crate-link]: https://crates.io/crates/srp
[docs-image]: https://docs.rs/srp/badge.svg
[docs-link]: https://docs.rs/srp/
[build-image]: https://github.com/RustCrypto/PAKEs/actions/workflows/srp.yml/badge.svg
[build-link]: https://github.com/RustCrypto/PAKEs/actions/workflows/srp.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.87+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260045-PAKEs

[//]: # (general links)

[RustCrypto]: https://github.com/RustCrypto
[Secure Remote Password]: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
[RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054
[RFC2945]: https://datatracker.ietf.org/doc/html/rfc2945
[HomeKit ADK]: https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/PAL/Crypto/OpenSSL/HAPOpenSSL.c
[`crypto-bigint`]: https://docs.rs/crypto-bigint
[`Digest`]: https://docs.rs/digest
[`sha2`]: https://crates.io/crates/sha2
