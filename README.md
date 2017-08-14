# PAKE [![Build Status](https://travis-ci.org/RustCrypto/PAKE.svg?branch=master)](https://travis-ci.org/RustCrypto/PAKE)
[Password-Authenticated Key Agreement][1] protocols implementation.

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

## License

All crates are licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.


[1]: https://en.wikipedia.org/wiki/Password-authenticated_key_agreement
[2]: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
[3]: https://en.wikipedia.org/wiki/Blinding_(cryptography)