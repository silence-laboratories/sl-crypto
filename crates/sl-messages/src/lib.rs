// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

pub mod message;
pub mod relay;

pub(crate) mod proto;

pub mod pairs;

pub use bytes::{Bytes, BytesMut};

pub mod signed {
    pub use crate::proto::signed::SignedMessage;
}

pub mod encrypted {
    pub use crate::proto::{
        encrypted::{
            EncryptedMessage, MessageBuilder, MessageKey,
            Scheme as DefaultEncryptionScheme,
        },
        scheme::aead::AeadX25519Builder,
        scheme::passthrough::{
            PassThroughEncryption, PassThroughEncryptionBuilder,
        },
        scheme::{
            EncryptionError, EncryptionScheme, EncryptionSchemeBuilder,
            PublicKeyError,
        },
    };
}

#[cfg(feature = "fast-ws")]
pub mod ws;
