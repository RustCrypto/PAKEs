//! Groups from [RFC 5054](https://tools.ietf.org/html/rfc5054)
//!
//! It is strongly recommended to use them instead of custom generated
//! groups. Additionally, it is not recommended to use `G_1024` and `G_1536`,
//! they are provided only for compatibility with the legacy software.

use crate::types::SrpGroup;
use crypto_bigint::BoxedUint;
use once_cell::sync::Lazy;

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

pub static G_6144: Lazy<SrpGroup> = Lazy::new(|| {
    SrpGroup::new(
        BoxedUint::from_be_slice_vartime(include_bytes!("groups/6144.bin")),
        BoxedUint::from_be_slice_vartime(&[5]),
    )
});

pub static G_8192: Lazy<SrpGroup> = Lazy::new(|| {
    SrpGroup::new(
        BoxedUint::from_be_slice_vartime(include_bytes!("groups/8192.bin")),
        BoxedUint::from_be_slice_vartime(&[19]),
    )
});
