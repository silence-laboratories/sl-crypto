use zeroize::{Zeroize, ZeroizeOnDrop};

/// EndemicOT Message 1
#[derive(
    Debug, Clone, bincode::Encode, bincode::Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct EndemicOTMsg1 {
    /// values r_0 and r_1 from OTReceiver to OTSender
    pub r_list: Vec<[[u8; 32]; 2]>, // size == BATCH_SIZE
}

/// EndemicOT Message 2
#[derive(
    Debug, Clone, bincode::Encode, bincode::Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct EndemicOTMsg2 {
    /// values m_b_0 and m_b_1 from OTSender to OTReceiver
    pub m_b_list: Vec<[[u8; 32]; 2]>, // size == BATCH_SIZE
}
