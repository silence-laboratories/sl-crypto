// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::marker::PhantomData;

use aead::{
    AeadCore, AeadInPlace, Key, KeyInit, Nonce, Tag,
    generic_array::typenum::Unsigned,
};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{array::Array, Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand_core::{CryptoRng, OsRng}; 
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::pairs::Pairs;

use super::{
    EncryptionError, EncryptionScheme, EncryptionSchemeBuilder, KeyExchange, MessageKey,
    PublicKeyError,
};

// Counter to create a unique nonce.
struct NonceCounter(u32);

impl NonceCounter {
    /// New counter initialized by 0.
    fn new() -> Self {
        Self(0)
    }

    /// Increment counter.
    fn next_nonce<S: AeadCore>(&mut self) -> Nonce<S> {
        // In our design, we use 3-5 nonces per unique symmetric key.
        // If the u32 counter overflows, then calling it is definitely
        // a misuse of the counter, and it's safer to crash than reuse
        // a nonce.
        self.0 = self.0.checked_add(1).expect("nonce overflow");

        let mut nonce = Nonce::<S>::default();
        nonce[..4].copy_from_slice(&self.0.to_le_bytes());

        nonce
    }
}

type SharedSecret = Zeroizing<Vec<u8>>; // 32 bytes for ML-KEM-768

/// Wrapper that stores bytes separately for AsRef<[u8]>
#[derive(Clone)]
pub struct MlKemEncapsulationKey {
    key: ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>,
    bytes: Vec<u8>, // Store bytes for AsRef<[u8]>
}

impl AsRef<[u8]> for MlKemEncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<'a> TryFrom<&'a [u8]> for MlKemEncapsulationKey {
    type Error = PublicKeyError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        // ML-KEM-768 encapsulation key is 1184 bytes
        type Ek = <MlKem768 as KemCore>::EncapsulationKey;
        if bytes.len() != 1184 {
            return Err(PublicKeyError);
        }
        // Convert slice to Array - need to use the correct size type
        // ML-KEM-768 uses a specific Array size, let's use TryFrom from hybrid_array
        let array: Array<u8, _> = bytes.try_into().map_err(|_| PublicKeyError)?;
        let key = Ek::from_bytes(&array);
        Ok(MlKemEncapsulationKey {
            key,
            bytes: bytes.to_vec(),
        })
    }
}

impl From<ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>> for MlKemEncapsulationKey {
    fn from(ek: ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>) -> Self {
        // Convert Array to Vec<u8>
        let bytes = ek.as_bytes().as_slice().to_vec();
        MlKemEncapsulationKey {
            key: ek,
            bytes,
        }
    }
}

impl From<MlKemEncapsulationKey> for ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params> {
    fn from(wrapper: MlKemEncapsulationKey) -> Self {
        wrapper.key
    }
}

pub struct AeadMlKemBuilder<S> {
    decapsulation_key: Option<ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>>,
    encapsulation_key: ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>,
    encapsulation_key_bytes: Vec<u8>, // Store bytes for public_key() method
    shared_secrets: Pairs<(SharedSecret, Vec<u8>, Vec<u8>), usize>,
    marker: PhantomData<S>,
}

/// The implementation of EncryptionScheme that uses ML-KEM for key
/// exchange and any implementation of `AeadInPlace`.
pub struct AeadMlKem<S> {
    encapsulation_key_bytes: Vec<u8>, // Own public key bytes (for decryption key derivation)
    shared_secrets: Pairs<(SharedSecret, Vec<u8>), usize>, // (shared_secret, receiver_pk_bytes)
    counter: NonceCounter,
    marker: PhantomData<S>,
}

pub struct AeadMlKemMessageKey<S: KeyInit + AeadCore> {
    cipher: S,
    nonce: Nonce<S>,
}

impl<S> AeadMlKemBuilder<S> {
    /// Generate a new [`AeadMlKem`] with the supplied RNG.
    pub fn new(rng: &mut impl rand_core::CryptoRng) -> Self {
        let (dk, ek) = MlKem768::generate(rng);
        let ek_bytes = ek.as_bytes().as_slice().to_vec();

        Self {
            decapsulation_key: Some(dk),
            encapsulation_key: ek,
            encapsulation_key_bytes: ek_bytes,
            shared_secrets: Pairs::new(),
            marker: PhantomData,
        }
    }
    
    // Internal implementation that uses trait object for ml-kem compatibility
    // ml-kem's encapsulate requires TryCryptoRng + ?Sized
    // In rand_core 0.9, CryptoRng implements TryCryptoRng
    fn establish_shared_secret_impl(
        &mut self,
        receiver_pk: &MlKemEncapsulationKey,
        rng: &mut impl CryptoRng
    ) -> Result<(SharedSecret, Vec<u8>), PublicKeyError> {
        use Encapsulate as _;
        let ek = &receiver_pk.key;
        // In rand_core 0.9, CryptoRng implements TryCryptoRng, so this works
        let (ct, k_send) = ek.encapsulate(rng)
            .map_err(|_| PublicKeyError)?;
        // SharedKey and Ciphertext are Array types, convert to Vec<u8>
        Ok((
            Zeroizing::new(k_send.as_slice().to_vec()),
            ct.as_slice().to_vec(),
        ))
    }
}

impl<S> KeyExchange for AeadMlKemBuilder<S>
where
    S: AeadInPlace + KeyInit + Send,
{
    type PublicKey = MlKemEncapsulationKey;
    type SharedSecret = SharedSecret; // 32 bytes for ML-KEM-768
    type KeyMaterial = Vec<u8>; // Ciphertext (1088 bytes for ML-KEM-768)

    fn establish_shared_secret(
        &mut self,
        receiver_pk: &Self::PublicKey,
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::SharedSecret, Vec<u8>), PublicKeyError> {
        // Encapsulate: sender picks shared secret and encrypts it with receiver's public key
        // ml-kem requires TryCryptoRng + ?Sized, so we use a trait object
        // In rand_core 0.9, CryptoRng implements TryCryptoRng
        self.establish_shared_secret_impl(receiver_pk, rng)    }

    fn receive_shared_secret(
        &mut self,
        _sender_pk: &Self::PublicKey, // Not used for decapsulation
        key_material: &Vec<u8>, // Ciphertext
    ) -> Result<Self::SharedSecret, PublicKeyError> {
        // Decapsulate: receiver recovers shared secret using own secret key
        use Decapsulate as _;
        let dk = self.decapsulation_key.as_ref().ok_or(PublicKeyError)?;
        // Convert bytes to fixed-size array for Ciphertext
        // ML-KEM-768 ciphertext is 1088 bytes
        // Ciphertext is a type alias: Array<u8, <K as KemCore>::CiphertextSize>
        // The type alias expects K: KemCore, so we use MlKem768 (which is Kem<MlKem768Params>)
        type Ct = ml_kem::Ciphertext<MlKem768>;
        if key_material.len() != 1088 {
            return Err(PublicKeyError);
        }
        // Convert Vec<u8> to Array using TryInto
        // Ciphertext is a type alias for Array, so we can use TryInto directly
        let ct: Ct = key_material.as_slice().try_into().map_err(|_| PublicKeyError)?;
        let k_recv = dk.decapsulate(&ct).map_err(|_| PublicKeyError)?;
        // SharedKey is an Array type, convert to Vec<u8>
        Ok(Zeroizing::new(k_recv.as_slice().to_vec()))
    }
}

impl<S> EncryptionSchemeBuilder for AeadMlKemBuilder<S>
where
    S: AeadInPlace + KeyInit + Send,
{
    type Scheme = AeadMlKem<S>;

    fn public_key(&self) -> &[u8] {
        &self.encapsulation_key_bytes
    }

    fn receiver_public_key(
        &mut self,
        receiver_index: usize,
        pk: &[u8],
    ) -> Result<(), PublicKeyError> {
        let receiver_pk = Self::PublicKey::try_from(pk)?;

        // This performs: (shared_secret, ciphertext) = encapsulate(receiver_pk)
        let (shared_secret, ciphertext) = self.establish_shared_secret(
            &receiver_pk,
            &mut OsRng,
        )?;

        // The ciphertext will be sent to the receiver later via get_key_material_for_receiver()
        self.shared_secrets.push(
            receiver_index,
            (shared_secret, ciphertext, pk.to_vec()),
        );
        Ok(())
    }

    // Override defaults for ML-KEM
    fn get_key_material_for_receiver(&self, receiver_index: usize) -> Option<&[u8]> {
        // Return the stored ciphertext
        self.shared_secrets
            .find_pair_or_err(receiver_index, ())
            .ok()
            .map(|(_, ct, _)| ct.as_slice())
    }

    fn receive_key_material(
        &mut self,
        sender_index: usize,
        key_material: &[u8],
    ) -> Result<(), PublicKeyError> {
        // Get sender's public key (stored during receiver_public_key)
        let (_, _, pk_bytes) = self.shared_secrets
            .find_pair_or_err(sender_index, PublicKeyError)?;
        let sender_pk_bytes = pk_bytes.clone();

        let sender_pk = Self::PublicKey::try_from(sender_pk_bytes.as_slice())?;

        // Decapsulate using KeyExchange trait method
        let shared_secret = self.receive_shared_secret(&sender_pk, &key_material.to_vec())?;

        // Update stored entry with the decapsulated shared secret
        // For now, we'll replace the entire entry
        // TODO: Add update method to Pairs or handle this differently
        let _old_entry = self.shared_secrets.pop_pair(sender_index);
        self.shared_secrets.push(
            sender_index,
            (shared_secret, key_material.to_vec(), sender_pk_bytes),
        );
        Ok(())
    }

    fn build(self) -> Self::Scheme {
        // Convert stored entries: (shared_secret, ciphertext, pk_bytes) -> (shared_secret, pk_bytes)
        let mut scheme_secrets = Pairs::new();
        for (idx, (shared_secret, _, pk_bytes)) in self.shared_secrets.iter() {
            scheme_secrets.push(*idx, (shared_secret.clone(), pk_bytes.clone()));
        }

        Self::Scheme {
            encapsulation_key_bytes: self.encapsulation_key_bytes,
            shared_secrets: scheme_secrets,
            counter: NonceCounter::new(),
            marker: PhantomData,
        }
    }
}

impl<S> MessageKey for AeadMlKemMessageKey<S>
where
    S: AeadInPlace + KeyInit,
{
    fn message_footer(&self) -> usize {
        S::TagSize::USIZE + S::NonceSize::USIZE
    }

    fn encrypt(
        self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), EncryptionError> {
        let (buffer, tail) = buffer
            .len()
            .checked_sub(S::TagSize::USIZE + S::NonceSize::USIZE)
            .and_then(|mid| buffer.split_at_mut_checked(mid))
            .ok_or(EncryptionError)?;

        let tag = self
            .cipher
            .encrypt_in_place_detached(&self.nonce, associated_data, buffer)
            .map_err(|_| EncryptionError)?;

        tail[..S::TagSize::USIZE].copy_from_slice(&tag);
        tail[S::TagSize::USIZE..].copy_from_slice(&self.nonce);

        Ok(())
    }
}

impl<S> EncryptionScheme for AeadMlKem<S>
where
    S: AeadInPlace + KeyInit + Send,
{
    type Key = AeadMlKemMessageKey<S>;

    fn encryption_key(
        &mut self,
        receiver: usize,
    ) -> Result<Self::Key, EncryptionError> {
        // Same as X25519: get (shared_secret, receiver_pk_bytes)
        let (shared_secret, receiver_pk_bytes) =
            self.shared_secrets.find_pair_or_err(receiver, EncryptionError)?;

        // Same key derivation as X25519: Sha256(receiver_pk || shared_secret)
        let key = Zeroizing::new(
            Sha256::new_with_prefix(receiver_pk_bytes.as_slice())
                .chain_update(shared_secret.as_slice())
                .finalize(),
        );

        let key = Key::<S>::from_slice(key.as_slice());
        let nonce = self.counter.next_nonce::<S>();
        let cipher = S::new(key);

        Ok(AeadMlKemMessageKey { cipher, nonce })
    }

    fn decrypt_message<'m>(
        &self,
        associated_data: &[u8],
        buffer: &'m mut [u8],
        sender: usize,
    ) -> Result<&'m mut [u8], EncryptionError> {
        let (buffer, tail) = buffer
            .len()
            .checked_sub(S::TagSize::USIZE + S::NonceSize::USIZE)
            .and_then(|mid| buffer.split_at_mut_checked(mid))
            .ok_or(EncryptionError)?;

        // Same as X25519: get (shared_secret, _sender_pk_bytes) but use own public key
        let (shared_secret, _sender_pk_bytes) =
            self.shared_secrets.find_pair_or_err(sender, EncryptionError)?;

        // Same key derivation as X25519: Sha256(own_pk || shared_secret)
        let key = Zeroizing::new(
            Sha256::new_with_prefix(self.encapsulation_key_bytes.as_slice())
                .chain_update(shared_secret.as_slice())
                .finalize(),
        );

        let key = Key::<S>::from_slice(key.as_slice());
        let nonce = Nonce::<S>::from_slice(&tail[S::TagSize::USIZE..]);
        let tag = Tag::<S>::from_slice(&tail[..S::TagSize::USIZE]);

        S::new(key)
            .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
            .map_err(|_| EncryptionError)?;

        Ok(buffer)
    }
}

