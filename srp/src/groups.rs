//! Groups from [RFC5054].
//!
//! It is strongly recommended to use them instead of custom generated groups.
//!
//! Additionally, it is NOT recommended to use [`G1024`] and [`G1536`],
//! they are provided only for compatibility with the legacy software.
//!
//! [RFC5054]: https://tools.ietf.org/html/rfc5054

use core::{
    any,
    fmt::{self, Debug},
};
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
        #[derive(Clone, Copy)]
        pub struct $name;
        group_trait_impls!($name, $g, $n);
    };
}

macro_rules! define_deprecated_group {
    ($name:ident, $g:expr, $n:expr, $doc:expr) => {
        /// DEPRECATED:
        #[doc = $doc]
        ///
        /// <div class="warning">
        /// <b>Warning: small group size!</b>
        ///
        /// It is recommended to use a group which is 2048-bits or larger.
        /// </div>
        #[derive(Clone, Copy)]
        #[deprecated(
            since = "0.7.0",
            note = "this group is too small to be secure. Prefer to use G2048+"
        )]
        pub struct $name;
        group_trait_impls!($name, $g, $n);
    };
}

macro_rules! group_trait_impls {
    ($name:ident, $g:expr, $n:expr) => {
        #[allow(deprecated)]
        impl Group for $name {
            const G: u64 = $g;
            const N: &'static [u8] = include_bytes!($n);
        }

        #[allow(deprecated)]
        impl Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let name = any::type_name::<$name>();
                let name = name.split("::").last().unwrap_or(name);

                write!(f, "{} {{ G: {}, N: 0x", name, Self::G)?;
                for byte in Self::N {
                    write!(f, "{byte:02X}")?;
                }
                write!(f, " }}")
            }
        }

        #[allow(deprecated)]
        impl<Rhs: Group> PartialEq<Rhs> for $name {
            fn eq(&self, _other: &Rhs) -> bool {
                Self::G == Rhs::G && Self::N == Rhs::N
            }
        }
    };
}

define_deprecated_group!(G1024, 2, "groups/1024.bin", "1024-bit group.");
define_deprecated_group!(G1536, 2, "groups/1536.bin", "1536-bit group.");
define_group!(G2048, 2, "groups/2048.bin", "2048-bit group.");
define_group!(G3072, 5, "groups/3072.bin", "3072-bit group.");
define_group!(G4096, 5, "groups/4096.bin", "4096-bit group.");

#[cfg(test)]
#[allow(deprecated)]
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
