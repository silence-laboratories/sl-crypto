// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Compatibility with encrypted messages produced by published sl-messages.

#![cfg(feature = "encrypted")]

use core::time::Duration;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sl_messages::{
    encrypted::{
        DefaultEncryptionScheme, EncryptedMessage, EncryptionSessionBuilder,
    },
    message::{MsgHdr, MsgId, MESSAGE_HEADER_SIZE},
};

const RECEIVER_SEED: [u8; 32] = [0x44; 32];
const RECEIVER_PUBLIC_KEY_HEX: &str =
    include_str!("vectors/published-pre1/receiver-public-key.hex");
const SENDER_PUBLIC_KEY_HEX: &str =
    include_str!("vectors/published-pre1/sender-public-key.hex");
const MESSAGE_HEX: &str = include_str!("vectors/published-pre1/message.hex");
const MESSAGE_ID_BYTES: [u8; 32] = [0x66; 32];
const AAD: [u8; 7] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6];
const BODY: [u8; 32] = sequence::<32>(0x20);
const TRAILER: [u8; 13] = sequence::<13>(0x70);
const SENDER: usize = 0;
const FLAGS: u16 = 0x1234;
const CHACHA20_POLY1305_OVERHEAD: usize = 28;

const fn sequence<const N: usize>(start: u8) -> [u8; N] {
    let mut bytes = [0; N];
    let mut index = 0;
    while index < N {
        bytes[index] = start.wrapping_add(index as u8);
        index += 1;
    }
    bytes
}

fn fixture(encoded: &str) -> Vec<u8> {
    hex::decode(encoded).expect("invalid hex fixture")
}

fn receiver() -> impl EncryptedMessage {
    // Recreate the published implementation's receiver secret and verify its
    // public key before configuring the published sender's public key.
    let mut rng = ChaCha20Rng::from_seed(RECEIVER_SEED);
    let mut receiver = DefaultEncryptionScheme::new(&mut rng);
    let receiver_public_key = fixture(RECEIVER_PUBLIC_KEY_HEX);
    let sender_public_key = fixture(SENDER_PUBLIC_KEY_HEX);
    assert_eq!(receiver.public_key(), receiver_public_key);
    receiver
        .receiver_public_key(&mut rng, SENDER, &sender_public_key)
        .unwrap();
    receiver.build()
}

#[test]
fn decrypts_message_from_published_pre1() {
    let mut receiver = receiver();
    let mut message = fixture(MESSAGE_HEX);

    let header = MsgHdr::try_from(message.as_slice()).unwrap();
    assert_eq!(header.id(), &MsgId::from(MESSAGE_ID_BYTES));
    assert_eq!(header.ttl(), Duration::from_secs(600));
    assert_eq!(header.flags(), FLAGS);

    let decrypted = receiver
        .decrypt::<[u8; 32]>(&mut message, AAD.len(), SENDER)
        .unwrap();

    assert_eq!(decrypted.data(), AAD);
    assert_eq!(decrypted.body(), &BODY);
    assert_eq!(decrypted.trailer(), TRAILER);

    drop(decrypted);

    // Decrypted payload and trailer are zeroized when their view is dropped.
    let plaintext = &message[MESSAGE_HEADER_SIZE + AAD.len()
        ..message.len() - CHACHA20_POLY1305_OVERHEAD];
    assert!(plaintext.iter().all(|byte| *byte == 0));
}

#[test]
fn rejects_tampered_message_from_published_pre1() {
    // Cover every authenticated region: header, additional data, ciphertext,
    // authentication tag, and nonce.
    let message = fixture(MESSAGE_HEX);
    for offset in [
        0,
        MESSAGE_HEADER_SIZE,
        MESSAGE_HEADER_SIZE + AAD.len(),
        message.len() - CHACHA20_POLY1305_OVERHEAD,
        message.len() - 1,
    ] {
        let mut receiver = receiver();
        let mut message = message.clone();
        message[offset] ^= 1;

        assert!(
            receiver
                .decrypt::<[u8; 32]>(&mut message, AAD.len(), SENDER)
                .is_none(),
            "accepted tampering at byte {offset}",
        );
    }
}
