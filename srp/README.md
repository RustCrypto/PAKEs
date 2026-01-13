# [RustCrypto]: Secure Remote Password

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [Secure Remote Password] password-authenticated
key exchange (PAKE) algorithm as described in [RFC5054].

Built on [`crypto-bigint`], a mathematical library designed with constant-time 
algorithms.

## About

This implementation is generic over hash functions using the [`Digest`] trait,
so you will need to choose a hash function, e.g. `Sha256` from [`sha2`] crate.

## ⚠️ Security Warning

This crate has never received an independent third party audit for security and
correctness.

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

Rust **1.85** or higher.

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
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260045-PAKEs

[//]: # (general links)

[RustCrypto]: https://github.com/RustCrypto
[Secure Remote Password]: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
[RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054
[`crypto-bigint`]: https://docs.rs/crypto-bigint
[`Digest`]: https://docs.rs/digest
[`sha2`]: https://crates.io/crates/sha2
