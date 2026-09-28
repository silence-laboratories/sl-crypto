use std::{env, fs, time::Duration};

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sl_messages::{
    encrypted::{
        DefaultEncryptionScheme, EncryptedMessage, EncryptionScheme,
        EncryptionSchemeBuilder, MessageKey,
    },
    message::MsgId,
};

const RECEIVER_SEED: [u8; 32] = [0x44; 32];
const SENDER_SEED: [u8; 32] = [0x55; 32];
const AAD: [u8; 7] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6];
const BODY: [u8; 32] = sequence::<32>(0x20);
const TRAILER: [u8; 13] = sequence::<13>(0x70);

const fn sequence<const N: usize>(start: u8) -> [u8; N] {
    let mut bytes = [0; N];
    let mut index = 0;
    while index < N {
        bytes[index] = start.wrapping_add(index as u8);
        index += 1;
    }
    bytes
}

fn main() {
    let output = env::args().nth(1).expect("output directory");

    let mut receiver_rng = ChaCha20Rng::from_seed(RECEIVER_SEED);
    let mut receiver = DefaultEncryptionScheme::new(&mut receiver_rng);
    let receiver_public_key = receiver.public_key().to_vec();

    let mut sender_rng = ChaCha20Rng::from_seed(SENDER_SEED);
    let mut sender = DefaultEncryptionScheme::new(&mut sender_rng);
    let sender_public_key = sender.public_key().to_vec();

    sender.receiver_public_key(1, &receiver_public_key).unwrap();
    receiver.receiver_public_key(0, &sender_public_key).unwrap();

    let mut sender = sender.build();
    let receiver = receiver.build();
    let message_id = MsgId::from([0x66; 32]);
    let message = sender
        .encryption_key(1)
        .unwrap()
        .message::<[u8; 32]>(Some(&AAD), TRAILER.len())
        .with_header(&message_id, Duration::from_secs(600), 0x1234)
        .with_body(|body| body.copy_from_slice(&BODY))
        .with_tailer(|trailer| trailer.copy_from_slice(&TRAILER))
        .encrypt()
        .unwrap();

    // Validate the fixture with the published implementation before writing it.
    let mut verification_message = message.to_vec();
    let decrypted = receiver
        .decrypt::<[u8; 32]>(&mut verification_message, AAD.len(), 0)
        .unwrap();
    assert_eq!(decrypted.data(), AAD);
    assert_eq!(decrypted.body(), &BODY);
    assert_eq!(decrypted.trailer(), TRAILER);

    fs::create_dir_all(&output).unwrap();
    fs::write(
        format!("{output}/receiver-public-key.hex"),
        hex::encode(receiver_public_key),
    )
    .unwrap();
    fs::write(
        format!("{output}/sender-public-key.hex"),
        hex::encode(sender_public_key),
    )
    .unwrap();
    fs::write(format!("{output}/message.hex"), hex::encode(message)).unwrap();
}
