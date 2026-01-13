//! Groups from [RFC 5054](https://tools.ietf.org/html/rfc5054)
//!
//! It is strongly recommended to use them instead of custom generated
//! groups. Additionally, it is not recommended to use `G1024` and `G_1536`,
//! they are provided only for compatibility with the legacy software.

use crypto_bigint::{
    BoxedUint, Odd, Resize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};

/// Group used for SRP computations.
pub trait Group {
    /// Group generator modulo `N`.
    const G: u64;

    /// Big endian bytes representing a large safe prime (`N = 2q + 1`, where `q` is prime) which
    /// acts as the modulus.
    const N: &'static [u8];

    /// Initialize group generator as a [`BoxedMontyForm`].
    fn generator() -> BoxedMontyForm {
        let n = BoxedUint::from_be_slice_vartime(Self::N);
        let n = BoxedMontyParams::new(Odd::new(n).expect("n should be odd"));
        BoxedMontyForm::new(BoxedUint::from(Self::G).resize(n.bits_precision()), &n)
    }
}

macro_rules! define_group {
    ($name:ident, $g:expr, $n:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name;

        impl Group for $name {
            const G: u64 = $g;
            const N: &'static [u8] = include_bytes!("groups/1024.bin");
        }
    };
}

define_group!(G1024, 2, "groups/1024.bin", "1024-bit group.");
define_group!(G1536, 2, "groups/1536.bin", "1536-bit group.");
define_group!(G2048, 2, "groups/2048.bin", "2048-bit group.");
define_group!(G3072, 5, "groups/3072.bin", "3072-bit group.");
define_group!(G4096, 5, "groups/4096.bin", "4096-bit group.");

#[cfg(test)]
mod tests {
    use super::{G1024, Group};
    use crate::utils::compute_k;
    use sha1::Sha1;

    #[test]
    fn test_k_1024_sha1() {
        let k = compute_k::<Sha1>(&G1024::generator()).to_be_bytes_trimmed_vartime();
        assert_eq!(&*k, include_bytes!("test/k_sha1_1024.bin"));
    }
}
