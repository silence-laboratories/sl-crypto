// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::{message::Bytes, signed::SignedMessage};

use super::{tags::ABORT_MESSAGE_TAG, traits::ProtocolParticipant};

/// Returns a passed error if `msg` is a valid abort message from `party_id`.
///
/// This helper only checks signature/message-shape validity for the
/// provided party key. It does not verify that `msg` belongs to the
/// abort round.
///
/// Callers are expected to pre-filter candidate messages, for example
/// by tracking pending abort IDs:
///
/// ```ignore
/// let abort_round = MessageRound::broadcast(setup, ABORT_MESSAGE_TAG);
/// if abort_round.is_pending(id) {
///     validate_abort_message(setup, msg, party_id, make_error)?;
/// }
/// ```
///
/// Return value handling:
/// - `Err(err(party_id))`: valid signature for `party_id`; treat this as
///   an authenticated abort and stop with that error.
/// - `Ok(())`: signature/message verification failed; when the caller has
///   already matched abort message ID, this means "abort-looking but not
///   authenticated" (e.g. invalid signature), so ignore it and continue.
pub fn validate_abort_message<P: ProtocolParticipant, E>(
    setup: &P,
    msg: &[u8],
    party_id: usize,
    err: impl FnOnce(usize) -> E,
) -> Result<(), E> {
    SignedMessage::<(), _>::verify(msg, setup.verifier(party_id))
        .map_or(Ok(()), |_| Err(err(party_id)))
}

/// Create an Abort Message.
pub fn create_abort_message<P>(setup: &P) -> Bytes
where
    P: ProtocolParticipant,
{
    SignedMessage::<(), _>::new(
        &setup.msg_id(None, ABORT_MESSAGE_TAG),
        setup.message_ttl(),
        0,
        0,
    )
    .sign(setup.signer())
}
