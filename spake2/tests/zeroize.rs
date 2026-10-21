//! Types holding secret material are zeroized on drop.

#![cfg(feature = "zeroize")]

use spake2::{Ed25519Group, Password, Spake2};
use zeroize::ZeroizeOnDrop;

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn secret_types_zeroize_on_drop() {
    assert_zeroize_on_drop::<Password>();
    assert_zeroize_on_drop::<Spake2<Ed25519Group>>();
}
