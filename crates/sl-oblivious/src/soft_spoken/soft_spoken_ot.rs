use super::DIGEST_SIZE;

#[derive(Debug, Default, Clone, bincode::Encode, bincode::Decode)]
pub struct SenderOTSeed {
    pub one_time_pad_enc_keys: Vec<Vec<[u8; DIGEST_SIZE]>>, // 256 * SOFT_SPOKEN_K * DIGEST
}

#[derive(Debug, Default, Clone, bincode::Encode, bincode::Decode)]
pub struct ReceiverOTSeed {
    pub random_choices: Vec<u8>,
    pub one_time_pad_dec_keys: Vec<Vec<[u8; DIGEST_SIZE]>>,
}
