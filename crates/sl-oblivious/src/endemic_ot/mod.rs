mod messages;
mod endemic_ot;

pub use messages::*;
pub use endemic_ot::*;

pub const BATCH_SIZE: usize = 256;

// size of u8 array to hold BATCH_SIZE.
pub const BATCH_SIZE_BYTES: usize = BATCH_SIZE / 8;

#[cfg(test)]
mod test {
    use sl_mpc_mate::SessionId;

    use crate::utils::ExtractBit;

    use super::{EndemicOTReceiver, EndemicOTSender, BATCH_SIZE};

    #[test]
    fn test_endemic_ot() {

        let mut rng = rand::thread_rng();
        let session_id = SessionId::random(&mut rng);

        let sender = EndemicOTSender::new(session_id, &mut rng);

        let (receiver, msg1) = EndemicOTReceiver::new(session_id, &mut rng);

        let (sender_output, msg2) = sender.process(msg1);

        let receiver_output = receiver.process(msg2);

        for i in 0..BATCH_SIZE {
            let sender_pad = &sender_output.one_time_pad_enc_keys[i];

            let rec_pad = &receiver_output.one_time_pad_decryption_keys[i];

            let bit = receiver_output.packed_random_choice_bits.extract_bit(i);
            if bit {
                assert_eq!(&sender_pad.rho_1, rec_pad);
            } else {
                assert_eq!(&sender_pad.rho_0, rec_pad);
            }
        }
    }
}
