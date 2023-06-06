pub mod serde_projective_point {
    use k256::{AffinePoint, ProjectivePoint};
    use serde::{Deserialize, Serialize};

    pub fn serialize<S>(data: &ProjectivePoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        data.to_affine().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ProjectivePoint, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let affine = AffinePoint::deserialize(deserializer)?;
        Ok(ProjectivePoint::from(affine))
    }
}

pub mod serde_projective_point_vec {
    use k256::{AffinePoint, ProjectivePoint};
    use serde::{Deserialize, Serialize};

    pub fn serialize<S>(data: &[ProjectivePoint], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let affine: Vec<AffinePoint> = data.iter().map(|p| p.to_affine()).collect();
        affine.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<ProjectivePoint>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let affine: Vec<AffinePoint> = Vec::<AffinePoint>::deserialize(deserializer)?;
        Ok(affine.iter().map(|p| ProjectivePoint::from(*p)).collect())
    }
}
