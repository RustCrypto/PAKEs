use scrypt::Params;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Scrypt parameters with Serde support for the example messages.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScryptParams(pub Params);

impl Serialize for ScryptParams {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.0.log_n(), self.0.r(), self.0.p()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ScryptParams {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (log_n, r, p) = Deserialize::deserialize(deserializer)?;
        Params::new(log_n, r, p)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::ScryptParams;
    use scrypt::Params;

    #[test]
    fn roundtrip() {
        let params = ScryptParams(Params::new(4, 8, 1).unwrap());
        let mut buf = [0; 32];
        let bytes = postcard::to_slice(&params, &mut buf).unwrap();
        assert_eq!(postcard::from_bytes::<ScryptParams>(bytes).unwrap(), params);
    }

    #[test]
    fn reject_invalid_params() {
        for params in [(64u8, 8u32, 1u32), (4, 0, 1), (4, 8, 0)] {
            let mut buf = [0; 32];
            let bytes = postcard::to_slice(&params, &mut buf).unwrap();
            assert!(postcard::from_bytes::<ScryptParams>(bytes).is_err());
        }
    }
}
