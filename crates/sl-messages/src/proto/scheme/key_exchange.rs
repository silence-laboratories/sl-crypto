// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::fmt::Debug;

use super::PublicKeyError;

/// Trait for key exchange mechanisms.
/// This is a supertrait of EncryptionSchemeBuilder
pub trait KeyExchange {
    type PublicKey: AsRef<[u8]>
        + for<'a> TryFrom<&'a [u8], Error = PublicKeyError>;

    type SharedSecret: AsRef<[u8]>;

    /// - For DH (X25519): `()` (no material)
    /// - For KEM (ML-KEM): `Vec<u8>` (ciphertext)
    type KeyMaterial: Default + AsRef<[u8]>;

    /// Error type for key exchange operations
    type Error: Debug;

    /// For X25519: Computes shared secret using DH
    /// For ML-KEM: Encapsulates shared secret using receiver's public key
    fn establish_shared_secret(
        &mut self,
        receiver_pk: &Self::PublicKey,
    ) -> Result<(Self::SharedSecret, Self::KeyMaterial), Self::Error>;

    /// For X25519: Same as establish_shared_secret (symmetric)
    /// For ML-KEM: Decapsulates shared secret using own secret key and ciphertext
    fn receive_shared_secret(
        &mut self,
        sender_pk: &Self::PublicKey,
        key_material: &Self::KeyMaterial,
    ) -> Result<Self::SharedSecret, Self::Error>;
}
