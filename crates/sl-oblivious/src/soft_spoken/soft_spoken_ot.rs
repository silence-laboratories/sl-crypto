use super::DIGEST_SIZE;

#[derive(Debug, Default)]
pub struct SenderOTSeed {
    pub one_time_pad_enc_keys: Vec<Vec<[u8; DIGEST_SIZE]>>,
}

#[derive(Debug, Default)]
pub struct ReceiverOTSeed {
    pub(crate) random_choices: Vec<u8>,
    pub(crate) one_time_pad_dec_keys: Vec<Vec<[u8; DIGEST_SIZE]>>,
}
