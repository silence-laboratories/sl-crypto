// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Compatibility with messages produced by the published pre.3 crate.

#![cfg(all(feature = "ml-kem", feature = "aes-gcm"))]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sl_msg_encrypt::{
    DataDecryption, EncryptionSession, EncryptionSessionBuilder,
    ml::{AesGcm, Builder, MlKem768, Session},
};

const RECEIVER_SEED: [u8; 32] = [0x11; 32];
const RECEIVER_PUBLIC_KEY_HEX: &str =
    include_str!("vectors/published-pre3/receiver-public-key.hex");
const MESSAGE_HEX: &str = include_str!("vectors/published-pre3/message.hex");
const AAD: [u8; 2] = [0, 1];
const PAYLOAD: [u8; 64] = payload();
const SENDER: usize = 0;
const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
const AES_GCM_OVERHEAD: usize = 28;

const fn payload() -> [u8; 64] {
    let mut payload = [0; 64];
    let mut index = 0;
    while index < payload.len() {
        payload[index] = index as u8;
        index += 1;
    }
    payload
}

fn fixture(encoded: &str) -> Vec<u8> {
    hex::decode(encoded).expect("invalid hex fixture")
}

fn receiver() -> Session<MlKem768, AesGcm> {
    // Recreate the published implementation's receiver decapsulation key. The
    // public-key assertion prevents changes to deterministic key generation
    // from silently making this test use a different receiver.
    let mut rng = ChaCha20Rng::from_seed(RECEIVER_SEED);
    let receiver = Builder::new(&mut rng);
    assert_eq!(receiver.public_key(), fixture(RECEIVER_PUBLIC_KEY_HEX));
    receiver.build()
}

#[test]
fn decrypts_message_from_published_pre3() {
    let mut receiver = receiver();
    let mut message = fixture(MESSAGE_HEX);

    assert!(receiver.expects_encapsulation(SENDER).is_some());

    let (aad, payload): (_, &[u8; 64]) = receiver
        .decrypt_data(SENDER, AAD.len(), &mut message)
        .unwrap();

    assert_eq!(aad, AAD);
    assert_eq!(payload, &PAYLOAD);
    assert_eq!(receiver.expects_encapsulation(SENDER), None);
}

#[test]
fn rejects_tampered_message_from_published_pre3() {
    // Cover every authenticated region in the old wire format: AAD,
    // encapsulation, ciphertext, authentication tag, and nonce.
    let message = fixture(MESSAGE_HEX);
    for offset in [
        0,
        AAD.len(),
        AAD.len() + ML_KEM_768_CIPHERTEXT_LEN,
        message.len() - AES_GCM_OVERHEAD,
        message.len() - 1,
    ] {
        let mut receiver = receiver();
        let mut message = message.clone();
        message[offset] ^= 1;

        assert!(
            receiver
                .decrypt_data::<[u8; 64]>(SENDER, AAD.len(), &mut message)
                .is_err(),
            "accepted tampering at byte {offset}",
        );
    }
}
