// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{collections::HashSet, time::Duration};

use crate::{
    message::{allocate_message, MessageTag},
    setup::{MessageRound, ProtocolParticipant, RoundMode},
};

use super::support::{AskRecorderRelay, TestParticipant};

#[test]
fn message_round_broadcast() {
    let setup = TestParticipant::new(4, 1);
    let tag = MessageTag::tag(11);
    let round = MessageRound::broadcast(&setup, tag);

    assert_eq!(round.pending_len(), 3);
    assert!(round.is_pending(&setup.msg_id_from(0, None, tag)));
    assert!(round.is_pending(&setup.msg_id_from(2, None, tag)));
    assert!(round.is_pending(&setup.msg_id_from(3, None, tag)));
    assert!(!round.is_pending(&setup.msg_id_from(1, None, tag)));
}

#[test]
fn message_round_p2p() {
    let setup = TestParticipant::new(4, 1);
    let tag = MessageTag::tag(12);
    let round = MessageRound::p2p(&setup, tag);

    assert_eq!(round.pending_len(), 3);
    assert!(round.is_pending(&setup.msg_id_from(0, Some(1), tag)));
    assert!(round.is_pending(&setup.msg_id_from(2, Some(1), tag)));
    assert!(round.is_pending(&setup.msg_id_from(3, Some(1), tag)));
    assert!(!round.is_pending(&setup.msg_id_from(0, None, tag)));
}

#[test]
fn message_round_from_parties_skips_me() {
    let setup = TestParticipant::new(4, 1);
    let tag = MessageTag::tag(13);
    let senders = vec![0, 1, 2];
    let round = MessageRound::from_parties(
        &setup,
        tag,
        &senders,
        RoundMode::Broadcast,
    );

    assert_eq!(round.pending_len(), 2);
    assert!(round.is_pending(&setup.msg_id_from(0, None, tag)));
    assert!(round.is_pending(&setup.msg_id_from(2, None, tag)));
    assert!(!round.is_pending(&setup.msg_id_from(1, None, tag)));
}

#[test]
fn message_round_from_parties_accepts_array_literal() {
    let setup = TestParticipant::new(4, 0);
    let tag = MessageTag::tag(16);
    let round =
        MessageRound::from_parties(&setup, tag, [1, 2], RoundMode::Broadcast);

    assert_eq!(round.pending_len(), 2);
    assert!(round.is_pending(&setup.msg_id_from(1, None, tag)));
    assert!(round.is_pending(&setup.msg_id_from(2, None, tag)));
    assert!(!round.is_pending(&setup.msg_id_from(3, None, tag)));
}

#[test]
fn message_round_from_parties_handles_large_input() {
    let setup = TestParticipant::new(300, 299);
    let tag = MessageTag::tag(18);
    let round =
        MessageRound::from_parties(&setup, tag, 0..256, RoundMode::Broadcast);

    assert_eq!(round.pending_len(), 256);
    assert!(round.is_pending(&setup.msg_id_from(0, None, tag)));
    assert!(round.is_pending(&setup.msg_id_from(255, None, tag)));
    assert!(!round.is_pending(&setup.msg_id_from(256, None, tag)));
}

#[test]
fn mark_received_message_removes_id() {
    let setup = TestParticipant::new(3, 1);
    let tag = MessageTag::tag(14);
    let mut round = MessageRound::broadcast(&setup, tag);

    let id = setup.msg_id_from(0, None, tag);
    let msg = allocate_message(&id, Duration::from_secs(5), 0, &[1, 2, 3]);

    assert!(round.mark_received_message(msg.as_ref()));
    assert!(!round.is_pending(&id));
    assert!(!round.mark_received_message(msg.as_ref()));
    assert!(!round.mark_received_message(&[]));
    assert_eq!(round.pending_len(), 1);
    assert!(!round.is_complete());
}

#[test]
fn pending_sender_and_mark_received_with_sender() {
    let setup = TestParticipant::new(4, 1);
    let tag = MessageTag::tag(19);
    let mut round = MessageRound::broadcast(&setup, tag);
    let id0 = setup.msg_id_from(0, None, tag);
    let id2 = setup.msg_id_from(2, None, tag);

    assert_eq!(round.pending_sender(&id0), Some(0));
    assert_eq!(round.pending_sender(&id2), Some(2));
    assert_eq!(round.mark_received_with_sender(&id2), Some(2));
    assert_eq!(round.pending_sender(&id2), None);
    assert!(!round.mark_received(&id2));

    let msg = allocate_message(&id0, Duration::from_secs(5), 0, &[1]);
    assert_eq!(round.pending_sender_message(msg.as_ref()), Some(0));
    assert_eq!(round.pending_sender_message(&[]), None);
    assert_eq!(
        round.mark_received_message_with_sender(msg.as_ref()),
        Some(0)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ask_pending_asks_all_pending_messages() {
    let setup = TestParticipant::new(4, 1);
    let tag = MessageTag::tag(15);
    let round = MessageRound::broadcast(&setup, tag);
    let relay = AskRecorderRelay::default();

    round.ask_pending(&relay).await.unwrap();

    let asks = relay.asks();
    let asked_ids = asks.iter().map(|(id, _)| *id).collect::<HashSet<_>>();
    let expected = setup
        .all_other_parties()
        .map(|sender| setup.msg_id_from(sender, None, tag))
        .collect::<HashSet<_>>();

    assert_eq!(asks.len(), 3);
    assert_eq!(asked_ids, expected);
    assert!(asks.iter().all(|(_, ttl)| *ttl == setup.message_ttl()));
}
