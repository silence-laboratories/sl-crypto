// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::message::MessageTag;

/// Tag for all setup messages.
pub const SETUP_MESSAGE_TAG: MessageTag = MessageTag::tag(0);

/// Tag of a broadcast message indicating that sender
/// won't participate in the protocol. The payload of
/// the message contains an error code.
pub const ABORT_MESSAGE_TAG: MessageTag = MessageTag::tag(u64::MAX);
