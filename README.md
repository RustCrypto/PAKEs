# SRP [![Build Status](https://travis-ci.org/RustCrypto/SRP.svg?branch=master)](https://travis-ci.org/RustCrypto/SRP) [![crates.io](https://img.shields.io/crates/v/srp.svg)](https://crates.io/crates/srp) [![Documentation](https://docs.rs/srp/badge.svg)](https://docs.rs/srp)
[Secure Remote Password][1] (SRP) protocol implementation.

This implementation uses little-endian representation of big integers and is
generic over hash functions using [`Digest`][2] trait, so you will need to
choose a hash function, e.g. `Sha256` from [`sha2`][3] crate. Additionally this
crate allows to use a specialized password hashing algorithms for private key
computation instead of method described in the SRP literature.

Currently compatability with over implementations was not tested.

## Warnings

This crate have not yet received any formal cryptographic and security reviews.

No efforts were yet taken in regards of [blinding][4] or erasing secrets from
the memory.

**USE AT YOUR OWN RISK.**

## License

This crate is licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.


[1]: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
[2]: https://crates.io/crates/digest
[3]: https://crates.io/crates/sha2
[4]: https://en.wikipedia.org/wiki/Blinding_(cryptography)