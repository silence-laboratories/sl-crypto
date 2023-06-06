use sl_mpc_mate::SessionId;

use crate::vsot::SenderOutput;

const KAPPA: usize = 256;
const KAPPA_BYTES: usize = KAPPA >> 3;
const S: usize = 80;
const L: usize = 2 * KAPPA + 2 * S;
const COT_BLOCK_SIZE_BYTES: usize = L >> 3;
const OT_WIDTH: usize = 2;
const KAPPA_OT: usize = KAPPA + S;
const L_PRIME: usize = L + KAPPA_OT;
const COT_EXTENDED_BLOCK_SIZE_BYTES: usize = L_PRIME >> 3;

pub struct COTReceiver<T> {
    session_id: SessionId,
    extended_packed_choices: Vec<u8>,
    seed_ot_results: SenderOutput,
    state: T,
}

pub struct Init {}

// impl COTReceiver<Init> {
//     pub fn new_with_output(session_id: SessionId) -> Self {}
// }
