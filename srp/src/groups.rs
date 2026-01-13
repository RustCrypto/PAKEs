//! Groups from [RFC5054].
//!
//! It is strongly recommended to use them instead of custom generated groups.
//!
//! Additionally, it is NOT recommended to use [`G1024`] and [`G1536`],
//! they are provided only for compatibility with the legacy software.
//!
//! [RFC5054]: https://tools.ietf.org/html/rfc5054

use bigint::{
    Odd, U1024, U1536, U2048, U3072, U4096,
    modular::{BoxedMontyForm, ConstMontyForm, ConstMontyParams, MontyParams},
};
use core::{
    any,
    fmt::{self, Debug},
};

/// Group used for SRP computations.
pub trait Group {
    /// Group elements.
    type Element: Into<BoxedMontyForm>;

    /// Group generator modulo `N` represented as `ConstMontyForm`, where `N` is a large safe prime
    /// (`N = 2q + 1`, where `q` is prime)
    const G: Self::Element;

    /// Initialize group generator as a [`BoxedMontyForm`].
    fn generator() -> BoxedMontyForm {
        Self::G.into()
    }
}

macro_rules! define_group {
    ($name:ident, $uint:ident, $g:expr, $doc:expr, $n:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Default, Eq, PartialEq)]
        pub struct $name;
        group_trait_impls!($name, $uint, $g, $n);
    };
}

macro_rules! define_deprecated_group {
    ($name:ident, $uint:ident, $g:expr, $doc:expr, $n:expr) => {
        /// DEPRECATED:
        #[doc = $doc]
        ///
        /// <div class="warning">
        /// <b>Warning: small group size!</b>
        ///
        /// It is recommended to use a group which is 2048-bits or larger.
        /// </div>
        #[derive(Clone, Copy, Default, Eq, PartialEq)]
        #[deprecated(
            since = "0.7.0",
            note = "this group is too small to be secure. Prefer to use G2048+"
        )]
        pub struct $name;
        group_trait_impls!($name, $uint, $g, $n);
    };
}

macro_rules! group_trait_impls {
    ($name:ident, $uint:ident, $g:expr, $n:expr) => {
        #[allow(deprecated)]
        impl ConstMontyParams<{ <$uint>::LIMBS }> for $name {
            const LIMBS: usize = <$uint>::LIMBS;
            const PARAMS: MontyParams<{ <$uint>::LIMBS }> =
                MontyParams::new_vartime(Odd::<$uint>::from_be_hex($n));
        }

        #[allow(deprecated)]
        impl Group for $name {
            type Element = ConstMontyForm<Self, { <$uint>::LIMBS }>;
            const G: Self::Element = ConstMontyForm::new(&<$uint>::from_u128($g));
        }

        #[allow(deprecated)]
        impl Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let name = any::type_name::<$name>();
                let name = name.split("::").last().unwrap_or(name);
                f.debug_struct(name)
                    .field("G", &Self::G.retrieve())
                    .field("N", &**Self::PARAMS.modulus())
                    .finish()
            }
        }
    };
}

// G1024
define_deprecated_group!(
    G1024,
    U1024,
    2,
    "1024-bit group",
    "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3"
);

// G1536
define_deprecated_group!(
    G1536,
    U1536,
    2,
    "1536-bit group",
    "9def3cafb939277ab1f12a8617a47bbbdba51df499ac4c80beeea9614b19cc4d5f4f5f556e27cbde51c6a94be4607a291558903ba0d0f84380b655bb9a22e8dcdf028a7cec67f0d08134b1c8b97989149b609e0be3bab63d47548381dbc5b1fc764e3f4b53dd9da1158bfd3e2b9c8cf56edf019539349627db2fd53d24b7c48665772e437d6c7f8ce442734af7ccb7ae837c264ae3a9beb87f8a2fe9b8b5292e5a021fff5e91479e8ce7a28c2442c6f315180f93499a234dcf76e3fed135f9bb"
);

// G2048
define_group!(
    G2048,
    U2048,
    2,
    "2048-bit group",
    "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73"
);

// G3072
define_group!(
    G3072,
    U3072,
    5,
    "3072-bit group",
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"
);

// G0496
define_group!(
    G4096,
    U4096,
    5,
    "4096-bit group",
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff"
);

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
