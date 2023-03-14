# [RustCrypto]: SPAKE2

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [SPAKE2] password-authenticated key-exchange algorithm.

[Documentation][docs-link]

## About

This library implements the SPAKE2 password-authenticated key exchange
("PAKE") algorithm. This allows two parties, who share a weak password, to
safely derive a strong shared secret (and therefore build an
encrypted+authenticated channel).

A passive attacker who eavesdrops on the connection learns no information
about the password or the generated secret. An active attacker
(man-in-the-middle) gets exactly one guess at the password, and unless they
get it right, they learn no information about the password or the generated
secret. Each execution of the protocol enables one guess. The use of a weak
password is made safer by the rate-limiting of guesses: no off-line
dictionary attack is available to the network-level attacker, and the
protocol does not depend upon having previously-established confidentiality
of the network (unlike e.g. sending a plaintext password over TLS).

The protocol requires the exchange of one pair of messages, so only one round
trip is necessary to establish the session key. If key-confirmation is
necessary, that will require a second round trip.

All messages are bytestrings. For the default security level (using the
Ed25519 elliptic curve, roughly equivalent to an 128-bit symmetric key), the
message is 33 bytes long.

This implementation is generic over a `Group`, which defines the cyclic
group to use, the functions which convert group elements and scalars to
and from bytestrings, and the three distinctive group elements used in
the blinding process. Only one such Group is implemented, named
`Ed25519Group`, which provides fast operations and high security, and is
compatible with my [python implementation](https://github.com/warner/python-spake2).

# What Is It Good For?

PAKE can be used in a pairing protocol, like the initial version of Firefox
Sync (the one with J-PAKE), to introduce one device to another and help them
share secrets. In this mode, one device creates a random code, the user
copies that code to the second device, then both devices use the code as a
one-time password and run the PAKE protocol. Once both devices have a shared
strong key, they can exchange other secrets safely.

PAKE can also be used (carefully) in a login protocol, where SRP is perhaps
the best-known approach. Traditional non-PAKE login consists of sending a
plaintext password through a TLS-encrypted channel, to a server which then
checks it (by hashing/stretching and comparing against a stored verifier). In
a PAKE login, both sides put the password into their PAKE protocol, and then
confirm that their generated key is the same. This nominally does not require
the initial TLS-protected channel. However note that it requires other,
deeper design considerations (the PAKE protocol must be bound to whatever
protected channel you end up using, else the attacker can wait for PAKE to
complete normally and then steal the channel), and is not simply a drop-in
replacement. In addition, the server cannot hash/stretch the password very
much (see the note on "Augmented PAKE" below), so unless the client is
willing to perform key-stretching before running PAKE, the server's stored
verifier will be vulnerable to a low-cost dictionary attack.

## ⚠️ Security Warning

This crate has never received an independent third party audit for security and
correctness.

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

Rust **1.60** or higher.

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

[crate-image]: https://img.shields.io/crates/v/spake2.svg
[crate-link]: https://crates.io/crates/spake2
[docs-image]: https://docs.rs/spake2/badge.svg
[docs-link]: https://docs.rs/spake2/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.60+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260045-PAKEs
[build-image]: https://github.com/RustCrypto/PAKEs/actions/workflows/spake2.yml/badge.svg
[build-link]: https://github.com/RustCrypto/PAKEs/actions/workflows/spake2.yml

[//]: # (general links)

[RustCrypto]: https://github.com/RustCrypto
[SPAKE2]: https://tools.ietf.org/id/draft-irtf-cfrg-spake2-10.html
