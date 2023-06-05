pub mod serde_projective_point {
    use elliptic_curve::{group::Curve, CurveArithmetic};
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    pub fn serialize<S, C: CurveArithmetic>(
        data: &C::ProjectivePoint,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        C::AffinePoint: Serialize,
    {
        data.to_affine().serialize(serializer)
    }

    pub fn deserialize<'de, D, C: CurveArithmetic>(
        deserializer: D,
    ) -> Result<C::ProjectivePoint, D::Error>
    where
        D: serde::Deserializer<'de>,
        C::AffinePoint: DeserializeOwned,
        C::ProjectivePoint: From<C::AffinePoint>,
    {
        let affine = C::AffinePoint::deserialize(deserializer)?;
        Ok(C::ProjectivePoint::from(affine))
    }
}

pub mod serde_projective_point_vec {
    use elliptic_curve::{group::Curve, CurveArithmetic};
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    pub fn serialize<S, C: CurveArithmetic>(
        data: &[C::ProjectivePoint],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        C::AffinePoint: Serialize + Clone,
    {
        let affine: Vec<C::AffinePoint> = data.iter().map(|p| p.to_affine()).collect();
        affine.serialize(serializer)
    }

    pub fn deserialize<'de, D, C: CurveArithmetic>(
        deserializer: D,
    ) -> Result<Vec<C::ProjectivePoint>, D::Error>
    where
        D: serde::Deserializer<'de>,
        C::AffinePoint: DeserializeOwned + Clone,
        C::ProjectivePoint: From<C::AffinePoint>,
    {
        let affine: Vec<C::AffinePoint> = Vec::<C::AffinePoint>::deserialize(deserializer)?;
        Ok(affine
            .iter()
            .map(|p| C::ProjectivePoint::from(*p))
            .collect())
    }
}
