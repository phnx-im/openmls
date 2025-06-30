//! This module contains the DMLsMessageIn and DMLsMessageOut structs, both wrappers around
//! MlsMessageIn and MlsMessageOut respectively. Each wrapper also contains an epoch field.

use std::ops::Deref;

use openmls_traits::dmls_traits::DmlsEpoch;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut},
    group::GroupId,
};

/// The [`DmlsMessageIn`] struct is a wrapper around [`MlsMessageIn`] that contains
/// an additional epoch field.
#[derive(PartialEq, Debug, Clone, TlsSize, TlsDeserialize, TlsDeserializeBytes)]
#[cfg_attr(feature = "test-utils", derive(TlsSerialize))]
pub struct DmlsMessageIn {
    /// The epoch of the message.
    pub epoch: DmlsEpoch,
    /// The actual message.
    pub message: MlsMessageIn,
}

impl DmlsMessageIn {
    /// Returns the epoch of the message.
    pub fn epoch(&self) -> &DmlsEpoch {
        &self.epoch
    }

    /// Returns the group ID of the message.
    pub fn group_id(&self) -> &GroupId {
        match &self.message.body {
            MlsMessageBodyIn::PublicMessage(msg) => msg.group_id(),
            MlsMessageBodyIn::PrivateMessage(msg) => msg.group_id(),
            _ => panic!("Invalid message type for group ID extraction"),
        }
    }
}

impl Deref for DmlsMessageIn {
    type Target = MlsMessageIn;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

/// The [`DmlsMessageOut`] struct is a wrapper around [`MlsMessageOut`] that contains
/// an additional epoch field.
#[derive(Debug, Clone, PartialEq, TlsSerialize, TlsSize)]
pub struct DmlsMessageOut {
    pub(super) epoch: DmlsEpoch,
    pub(super) message: MlsMessageOut,
}

impl DmlsMessageOut {
    /// Returns the epoch of the message.
    pub fn epoch(&self) -> &DmlsEpoch {
        &self.epoch
    }
}

impl Deref for DmlsMessageOut {
    type Target = MlsMessageOut;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}
