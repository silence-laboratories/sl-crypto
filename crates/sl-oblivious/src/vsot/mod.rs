mod messages;
/// VSOT Sender
mod sender;

mod receiver;

pub use messages::*;
pub use receiver::*;
pub use sender::*;

use thiserror::Error;

pub const BATCH_SIZE: usize = 256;

// size of u8 array to hold BATCH_SIZE. FIXME better name!!!
pub const BATCH_SIZE_BITS: usize = BATCH_SIZE / 8;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
/// VSOT errors
pub enum VSOTError {
    /// Invalid Batch size
    #[error("Invalid batch size")]
    InvalidBatchSize,
    /// Invalid Dlog proof for message 1
    #[error("Invalid DLog proof for message 1")]
    InvalidDLogProof,
    /// Invalid challenge response by the receiver
    #[error("Invalid challenge response by the receiver")]
    InvalidChallegeResponse,
    /// Invalid data count
    #[error("Invalid data count, must be equal to batch size")]
    InvalidDataCount,
    /// Invalid rho_w hash
    #[error("Invalid rho_w hash")]
    InvalidRhoHash,
}

#[cfg(test)]
mod test {
    use sl_mpc_mate::SessionId;

    use crate::utils::ExtractBit;

    use super::{VSOTReceiver, VSOTSender, BATCH_SIZE};

    #[test]
    fn test_vsot() {
        let mut rng = rand::thread_rng();
        let session_id = SessionId::random(&mut rng);
        let sender = VSOTSender::new(session_id, &mut rng);
        let (sender, msg1) = sender.process();

        let rec = VSOTReceiver::new(session_id, &mut rng);
        let (rec, msg2) = rec.process(msg1).unwrap();

        let (sender, msg3) = sender.process(msg2).unwrap();

        let (rec, msg4) = rec.process(msg3).unwrap();

        let (sender_output, msg5) = sender.process(msg4).unwrap();

        let rec_output = rec.process(msg5).unwrap();

        for i in 0..BATCH_SIZE {
            let sender_pad =
                &sender_output.one_time_pad_enc_keys[i as usize];

            let rec_pad =
                &rec_output.one_time_pad_decryption_keys[i as usize];

            let bit = rec_output
                .packed_random_choice_bits
                .extract_bit(i as usize);
            if bit {
                assert_eq!(&sender_pad.rho_1, rec_pad);
            } else {
                assert_eq!(&sender_pad.rho_0, rec_pad);
            }
        }
    }
}
