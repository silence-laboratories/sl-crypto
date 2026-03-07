// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use tokio::time::timeout;

use crate::{
    message::{allocate_message, MessageTag, MsgId},
    relay::{BufferedMsgRelay, Relay, SimpleMessageRelay},
    setup::{MessageRound, ProtocolParticipant},
};

use super::support::{TestParticipant, TEST_TIMEOUT};

#[tokio::test(flavor = "multi_thread")]
async fn message_round_wait_for_end_to_end() {
    let setup = TestParticipant::new(4, 1);
    let tag = MessageTag::tag(17);
    let other_tag = MessageTag::tag(99);
    let mut round = MessageRound::broadcast(&setup, tag);

    let service = SimpleMessageRelay::new();
    let tx = service.connect();
    let mut relay = BufferedMsgRelay::new(service.connect());

    // Ask for round messages and one extra message that does not belong
    // to the round. The extra one should stay buffered.
    round.ask_pending(&relay).await.unwrap();
    let extra_id = setup.msg_id_from(0, None, other_tag);
    relay.ask(&extra_id, setup.message_ttl()).await.unwrap();

    tx.send(allocate_message(
        &setup.msg_id_from(3, None, tag),
        setup.message_ttl(),
        0,
        &[3],
    ))
    .await
    .unwrap();
    tx.send(allocate_message(
        &setup.msg_id_from(0, None, tag),
        setup.message_ttl(),
        0,
        &[0],
    ))
    .await
    .unwrap();
    tx.send(allocate_message(
        &setup.msg_id_from(2, None, tag),
        setup.message_ttl(),
        0,
        &[2],
    ))
    .await
    .unwrap();
    tx.send(allocate_message(&extra_id, setup.message_ttl(), 0, &[10]))
        .await
        .unwrap();

    for _ in 0..3 {
        let msg =
            timeout(TEST_TIMEOUT, relay.wait_for(|id| round.is_pending(id)))
                .await
                .unwrap()
                .unwrap();
        assert!(round.mark_received_message(msg.as_ref()));
    }

    assert!(round.is_complete());
    assert_eq!(round.pending_len(), 0);
    assert_eq!(relay.buffered_len(), 1);

    let msg = timeout(TEST_TIMEOUT, relay.next()).await.unwrap().unwrap();
    assert_eq!(<&MsgId>::try_from(msg.as_ref()).ok(), Some(&extra_id));
}
