use std::{env, fs};

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sl_msg_encrypt::{
    DataDecryption, DataEncryption, EncryptionScheme,
    EncryptionSchemeBuilder,
    ml::{AesGcm, Builder, MlKem768},
};

const RECEIVER_SEED: [u8; 32] = [0x11; 32];
const SENDER_SEED: [u8; 32] = [0x22; 32];
const ENCAPSULATION_SEED: [u8; 32] = [0x33; 32];

fn main() {
    let output = env::args().nth(1).expect("output directory");

    let mut receiver_rng = ChaCha20Rng::from_seed(RECEIVER_SEED);
    let receiver = Builder::<MlKem768, AesGcm>::new(&mut receiver_rng);
    let public_key = receiver.public_key().to_vec();

    let mut sender_rng = ChaCha20Rng::from_seed(SENDER_SEED);
    let mut sender = Builder::<MlKem768, AesGcm>::new(&mut sender_rng);
    let mut encapsulation_rng = ChaCha20Rng::from_seed(ENCAPSULATION_SEED);
    sender
        .receiver_public_key(&mut encapsulation_rng, 1, &public_key)
        .unwrap();

    let payload = core::array::from_fn::<_, 64, _>(|index| index as u8);
    let mut message = Vec::new();
    sender
        .build()
        .encryption_key(1)
        .unwrap()
        .encrypt_data(&[0, 1], &payload, &mut message)
        .unwrap();

    // Validate the fixture with the published implementation before writing it.
    let mut verification_message = message.clone();
    let (_, decrypted): (_, &[u8; 64]) = receiver
        .build()
        .decrypt_data(0, 2, &mut verification_message)
        .unwrap();
    assert_eq!(decrypted, &payload);

    fs::create_dir_all(&output).unwrap();
    fs::write(
        format!("{output}/receiver-public-key.hex"),
        hex::encode(public_key),
    )
    .unwrap();
    fs::write(format!("{output}/message.hex"), hex::encode(message)).unwrap();
}
