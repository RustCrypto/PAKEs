# RustCrypto: PAKEs [![Build Status](https://travis-ci.org/RustCrypto/PAKEs.svg?branch=master)](https://travis-ci.org/RustCrypto/PAKEs)
[Password-Authenticated Key Agreement][1] protocols implementation.

[![dependency status](https://deps.rs/repo/github/RustCrypto/PAKEs/status.svg)](https://deps.rs/repo/github/RustCrypto/PAKEs)

## Warnings

Crates in this repository have not yet received any formal cryptographic and
security reviews.

No efforts were yet taken in regards of [blinding][3] or erasing secrets from
the memory.

**USE AT YOUR OWN RISK.**

## Supported algorithms

| Name      | Crates.io  | Documentation  |
| --------- |:----------:| :-----:|
| [SRP][2]  | [![crates.io](https://img.shields.io/crates/v/srp.svg)](https://crates.io/crates/srp) | [![Documentation](https://docs.rs/srp/badge.svg)](https://docs.rs/srp) |
| [spake2][4]  | [![crates.io](https://img.shields.io/crates/v/spake2.svg)](https://crates.io/crates/spake2) | [![Documentation](https://docs.rs/spake2/badge.svg)](https://docs.rs/spake2) |

## Rust version requirements

The MSRV (Minimum Supported Rust Version) for `srp` is 1.32.0. The MSRV for
`spake2` is 1.36.0 . If/when these change, it will be noted in the changelog,
and the crate semvers will be updated. So downstream projects should depend
upon e.g. `spake2 = "0.3"` to avoid picking up new versions that would
require a newer compiler.

SRP-v0.4.1 actually works with rustc-1.31.1, but this will probably be
changed in the next release.

SPAKE2 required rustc-1.32 beginning with spake2-v0.2.0 .

SPAKE2 started requiring rustc-1.36 beginning with spake2-v0.3.0 .

Our CI scripts check all builds against a pinned version of rustc to test the
intended MSRV. Sometimes upstream dependencies make surprising changes that
could require a newer version of rustc, without changes to the source code in
this repository, but hopefully this won't happen very frequently.

## License

All crates are licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[1]: https://en.wikipedia.org/wiki/Password-authenticated_key_agreement
[2]: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
[3]: https://en.wikipedia.org/wiki/Blinding_(cryptography)
[4]: https://www.di.ens.fr/~mabdalla/papers/AbPo05a-letter.pdf
