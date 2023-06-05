pub mod serde_projective_point {
    use elliptic_curve::{group::Curve, Group};
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    pub fn serialize<S, P: Group + Curve>(data: &P, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        P::AffineRepr: Serialize,
    {
        data.to_affine().serialize(serializer)
    }

    pub fn deserialize<'de, D, P: Group + Curve>(deserializer: D) -> Result<P, D::Error>
    where
        D: serde::Deserializer<'de>,
        P::AffineRepr: DeserializeOwned,
        P: From<P::AffineRepr>,
    {
        let affine = P::AffineRepr::deserialize(deserializer)?;
        Ok(P::from(affine))
    }
}

pub mod serde_projective_point_vec {
    use elliptic_curve::{group::Curve, Group};
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    pub fn serialize<S, P: Group + Curve>(data: &[P], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        P::AffineRepr: Serialize,
    {
        let affine: Vec<P::AffineRepr> = data.iter().map(|p| p.to_affine()).collect();
        affine.serialize(serializer)
    }

    pub fn deserialize<'de, D, P: Group + Curve>(deserializer: D) -> Result<Vec<P>, D::Error>
    where
        D: serde::Deserializer<'de>,
        P::AffineRepr: DeserializeOwned,
        P: From<P::AffineRepr>,
    {
        let affine: Vec<P::AffineRepr> = Vec::<P::AffineRepr>::deserialize(deserializer)?;
        Ok(affine.iter().map(|p| P::from(*p)).collect())
    }
}
