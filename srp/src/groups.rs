//! Groups from [RFC 5054](https://tools.ietf.org/html/rfc5054)
//!
//! It is strongly recommended to use them instead of custom generated
//! groups. Additionally it is not recommended to use `G_1024` and `G_1536`,
//! they are provided only for compatibility with the legacy software.
use lazy_static::lazy_static;
use num_bigint::{BigInt, Sign};

use crate::types::SrpGroup;

lazy_static! {
    pub static ref G_1024: SrpGroup = SrpGroup {
        n: BigInt::from_bytes_be(Sign::Plus, include_bytes!("groups/1024.bin")),
        g: BigInt::from_bytes_be(Sign::Plus, &[2]),
    };
}

lazy_static! {
    pub static ref G_1536: SrpGroup = SrpGroup {
        n: BigInt::from_bytes_be(Sign::Plus, include_bytes!("groups/1536.bin")),
        g: BigInt::from_bytes_be(Sign::Plus, &[2]),
    };
}

lazy_static! {
    pub static ref G_2048: SrpGroup = SrpGroup {
        n: BigInt::from_bytes_be(Sign::Plus, include_bytes!("groups/2048.bin")),
        g: BigInt::from_bytes_be(Sign::Plus, &[2]),
    };
}

lazy_static! {
    pub static ref G_3072: SrpGroup = SrpGroup {
        n: BigInt::from_bytes_be(Sign::Plus, include_bytes!("groups/3072.bin")),
        g: BigInt::from_bytes_be(Sign::Plus, &[5]),
    };
}

lazy_static! {
    pub static ref G_4096: SrpGroup = SrpGroup {
        n: BigInt::from_bytes_be(Sign::Plus, include_bytes!("groups/4096.bin")),
        g: BigInt::from_bytes_be(Sign::Plus, &[5]),
    };
}

lazy_static! {
    pub static ref G_6144: SrpGroup = SrpGroup {
        n: BigInt::from_bytes_be(Sign::Plus, include_bytes!("groups/6144.bin")),
        g: BigInt::from_bytes_be(Sign::Plus, &[5]),
    };
}

lazy_static! {
    pub static ref G_8192: SrpGroup = SrpGroup {
        n: BigInt::from_bytes_be(Sign::Plus, include_bytes!("groups/8192.bin")),
        g: BigInt::from_bytes_be(Sign::Plus, &[19]),
    };
}
