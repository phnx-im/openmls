//! This module contains wrapper functions around the [`MlsGroup`] API.

use openmls_traits::{dmls_traits::OpenDmlsProvider, signatures::Signer};
use thiserror::Error;

#[cfg(doc)]
use crate::group::mls_group::MlsGroup;

use crate::{
    framing::{MlsMessageBodyIn, MlsMessageOut, ProcessedMessage, ProtocolMessage},
    group::{
        dmls::dmls_message::{DmlsMessageIn, DmlsMessageOut},
        AddMembersError, ProcessMessageError, SelfUpdateError,
    },
    prelude::{group_info::GroupInfo, KeyPackage, LeafNodeParameters, Welcome},
    storage::OpenMlsProvider,
};

use super::dmls_group::DmlsGroup;

/// Contains the messages that are produced by committing.
#[derive(Debug, Clone)]
pub struct DmlsCommitMessageBundle {
    /// The DMLs message that contains the epoch and the MLS message.
    pub dmls_message: DmlsMessageOut,
    /// The welcome message that is produced by the commit.
    pub welcome: Option<Welcome>,
    /// The group info that is produced by the commit.
    pub group_info: Option<GroupInfo>,
}

/// Error processing a DMLs message.
#[derive(Debug, Error)]
pub enum ProcessDmlsMessageError<StorageError> {
    /// DMLS message does not contain Public or Private MLS message.
    #[error("DMLS message does not contain Public or Private MLS message.")]
    IncompatibleMessageType,
    /// Error loading DMLS group state.
    #[error("Error loading DMLS group state: {0}")]
    StorageError(StorageError),
    /// Error processing the MLS message.
    #[error("Error processing MLS message: {0}")]
    ProcessMessageError(#[from] ProcessMessageError),
}

impl DmlsGroup {
    /// Add members to the group.
    pub fn add_members<Provider: OpenDmlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        key_packages: &[KeyPackage],
    ) -> Result<
        (DmlsMessageOut, MlsMessageOut, Option<GroupInfo>),
        AddMembersError<<Provider as OpenMlsProvider>::StorageError>,
    > {
        let epoch = self.derive_epoch_id(provider).unwrap();
        let provider = provider.provider_for_epoch(epoch.clone());
        let (mls_message, welcome, group_info) =
            self.0.add_members(&provider, signer, key_packages)?;
        let dmls_message = DmlsMessageOut {
            epoch,
            message: mls_message,
        };
        Ok((dmls_message, welcome, group_info))
    }

    /// Load the correct group and process a message.
    pub fn process_message<Provider: OpenDmlsProvider>(
        &mut self,
        provider: &Provider,
        message: DmlsMessageIn,
    ) -> Result<
        ProcessedMessage,
        ProcessDmlsMessageError<<Provider as OpenMlsProvider>::StorageError>,
    > {
        let DmlsMessageIn { epoch, message } = message;
        let protocol_message: ProtocolMessage = match message.body {
            MlsMessageBodyIn::PublicMessage(public_message_in) => public_message_in.into(),
            MlsMessageBodyIn::PrivateMessage(private_message_in) => private_message_in.into(),
            _ => {
                return Err(ProcessDmlsMessageError::IncompatibleMessageType);
            }
        };
        let provider = provider.provider_for_epoch(epoch);
        Ok(self.0.process_message(&provider, protocol_message)?)
    }

    /// DMLS wrapper around the [`MlsGroup::self_update`] function.
    pub fn self_update<Provider: OpenDmlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        leaf_node_parameters: LeafNodeParameters,
    ) -> Result<DmlsCommitMessageBundle, SelfUpdateError<<Provider as OpenMlsProvider>::StorageError>>
    {
        let epoch = self.derive_epoch_id(provider).unwrap();
        let provider = provider.provider_for_epoch(epoch.clone());
        let (message, welcome, group_info) = self
            .0
            .self_update(&provider, signer, leaf_node_parameters)?
            .into_contents();
        let dmls_message = DmlsMessageOut { epoch, message };
        Ok(DmlsCommitMessageBundle {
            dmls_message,
            welcome,
            group_info,
        })
    }

    /// Clear a pending commit
    pub fn clear_pending_commit<Provider: OpenDmlsProvider>(
        &mut self,
        provider: &Provider,
    ) -> Result<(), <Provider as OpenMlsProvider>::StorageError> {
        let epoch = self.derive_epoch_id(provider).unwrap();
        let provider = provider.provider_for_epoch(epoch.clone());
        self.0.clear_pending_commit(provider.storage())?;
        Ok(())
    }
}
