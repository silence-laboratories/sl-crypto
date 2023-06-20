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

pub mod serde_u_array {
    use std::fmt;

    use serde::{
        de::{self, SeqAccess, Visitor},
        ser::SerializeTuple,
        Deserializer,
    };

    use crate::soft_spoken_mod::{COT_EXTENDED_BLOCK_SIZE_BYTES, KAPPA_DIV_SOFT_SPOKEN_K};

    pub fn serialize<S>(
        data: &[[u8; COT_EXTENDED_BLOCK_SIZE_BYTES]; KAPPA_DIV_SOFT_SPOKEN_K],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(KAPPA_DIV_SOFT_SPOKEN_K)?;
        for elem in data.iter() {
            for e in elem.iter() {
                seq.serialize_element(e)?;
            }
        }

        seq.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<[[u8; COT_EXTENDED_BLOCK_SIZE_BYTES]; KAPPA_DIV_SOFT_SPOKEN_K], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor;

        impl<'de> Visitor<'de> for ArrayVisitor {
            type Value = [[u8; COT_EXTENDED_BLOCK_SIZE_BYTES]; KAPPA_DIV_SOFT_SPOKEN_K];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(&format!(
                    "a sequence of bytes in the format of [[u8;{}];{}]",
                    COT_EXTENDED_BLOCK_SIZE_BYTES, KAPPA_DIV_SOFT_SPOKEN_K
                ))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut array = [[0; COT_EXTENDED_BLOCK_SIZE_BYTES]; KAPPA_DIV_SOFT_SPOKEN_K];
                for i in 0..KAPPA_DIV_SOFT_SPOKEN_K {
                    for j in 0..COT_EXTENDED_BLOCK_SIZE_BYTES {
                        array[i][j] = seq.next_element()?.ok_or_else(|| {
                            de::Error::invalid_length(i * COT_EXTENDED_BLOCK_SIZE_BYTES + j, &self)
                        })?;
                    }
                }
                Ok(array)
            }
        }

        let array = deserializer.deserialize_tuple(
            KAPPA_DIV_SOFT_SPOKEN_K * COT_EXTENDED_BLOCK_SIZE_BYTES,
            ArrayVisitor,
        )?;
        Ok(array)
    }
}
