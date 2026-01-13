//! Groups from [RFC 5054](https://tools.ietf.org/html/rfc5054)
//!
//! It is strongly recommended to use them instead of custom generated
//! groups. Additionally, it is not recommended to use `G_1024` and `G_1536`,
//! they are provided only for compatibility with the legacy software.

use crypto_bigint::{
    BoxedUint, Odd, Resize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use once_cell::sync::Lazy;

/// Group used for SRP computations
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SrpGroup {
    /// A large safe prime (N = 2q+1, where q is prime)
    pub n: BoxedMontyParams,
    /// A generator modulo N
    pub g: BoxedMontyForm,
}

impl SrpGroup {
    /// Initialize a new group from the given boxed integers.
    pub fn new(n: BoxedUint, g: BoxedUint) -> Self {
        let n = BoxedMontyParams::new(Odd::new(n).expect("n should be odd"));
        let g = BoxedMontyForm::new(g.resize(n.bits_precision()), &n);
        Self { n, g }
    }
}

pub static G_1024: Lazy<SrpGroup> = Lazy::new(|| {
    SrpGroup::new(
        BoxedUint::from_be_slice_vartime(include_bytes!("groups/1024.bin")),
        BoxedUint::from_be_slice_vartime(&[2]),
    )
});

pub static G_1536: Lazy<SrpGroup> = Lazy::new(|| {
    SrpGroup::new(
        BoxedUint::from_be_slice_vartime(include_bytes!("groups/1536.bin")),
        BoxedUint::from_be_slice_vartime(&[2]),
    )
});

pub static G_2048: Lazy<SrpGroup> = Lazy::new(|| {
    SrpGroup::new(
        BoxedUint::from_be_slice_vartime(include_bytes!("groups/2048.bin")),
        BoxedUint::from_be_slice_vartime(&[2]),
    )
});

pub static G_3072: Lazy<SrpGroup> = Lazy::new(|| {
    SrpGroup::new(
        BoxedUint::from_be_slice_vartime(include_bytes!("groups/3072.bin")),
        BoxedUint::from_be_slice_vartime(&[5]),
    )
});

pub static G_4096: Lazy<SrpGroup> = Lazy::new(|| {
    SrpGroup::new(
        BoxedUint::from_be_slice_vartime(include_bytes!("groups/4096.bin")),
        BoxedUint::from_be_slice_vartime(&[5]),
    )
});

#[cfg(test)]
mod tests {
    use crate::groups::G_1024;
    use crate::utils::compute_k;
    use sha1::Sha1;

    #[test]
    fn test_k_1024_sha1() {
        let k = compute_k::<Sha1>(&G_1024).to_be_bytes_trimmed_vartime();
        assert_eq!(&*k, include_bytes!("test/k_sha1_1024.bin"));
    }
}
