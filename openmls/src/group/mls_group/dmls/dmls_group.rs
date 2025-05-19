//! This module contains the [`DmlsGroup`] struct, which is a wrapper around
//! [`MlsGroup`] that provides DMLs-specific functionality.
use std::{mem, ops::Deref};

use openmls_traits::{
    dmls_traits::{DmlsEpoch, DmlsStorageProvider as _, OpenDmlsProvider},
    random::OpenMlsRand,
    signatures::Signer,
    storage::StorageProvider as _,
};
use thiserror::Error;

use crate::{
    group::{
        mls_group::builder::MlsGroupBuilder, ExportSecretError, GroupId, MergeCommitError,
        MlsGroup, MlsGroupCreateConfig, MlsGroupState, MlsGroupStateError, NewGroupError,
        StagedCommit, StagedWelcome, WelcomeError,
    },
    prelude::CredentialWithKey,
    schedule::GroupEpochSecrets,
    storage::{DmlsStorageProvider, OpenMlsProvider},
};

//// The [`DmlsGroup`] struct is a wrapper around [`MlsGroup`] that provides
/// DMLs-specific functionality.
pub struct DmlsGroup(pub(super) MlsGroup);

impl Deref for DmlsGroup {
    type Target = MlsGroup;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Error type for merging pending commits in DMLS groups.
#[derive(Debug, Error)]
pub enum DmlsMergePendingError<StorageError> {
    /// Error merging the commit.
    #[error(transparent)]
    DmlsMergeError(#[from] DmlsMergeError<StorageError>),
    /// Group state error.
    #[error(transparent)]
    GroupStateError(#[from] MlsGroupStateError),
}

/// Error type for merging commits in DMLS groups.
#[derive(Debug, Error)]
pub enum DmlsMergeError<StorageError> {
    /// Error merging the commit.
    #[error(transparent)]
    MergeCommitError(#[from] MergeCommitError<StorageError>),
    /// Error exporting the epoch ID.
    #[error(transparent)]
    ExportSecretError(#[from] ExportSecretError),
}

impl DmlsGroup {
    /// Creates a new [`DmlsGroup`] instance.
    pub fn new<Provider: OpenDmlsProvider>(
        provider: &Provider,
        signer: &impl Signer,
        mls_group_create_config: &MlsGroupCreateConfig,
        credential_with_key: CredentialWithKey,
    ) -> Result<Self, NewGroupError<<Provider as OpenMlsProvider>::StorageError>> {
        let ciphersuite = mls_group_create_config.ciphersuite();
        let rand_temp_epoch = provider
            .rand()
            .random_vec(ciphersuite.hash_length())
            .unwrap();
        let temp_epoch = DmlsEpoch(rand_temp_epoch);
        let temp_epoch_provider = provider.provider_for_epoch(temp_epoch.clone());
        let group = MlsGroupBuilder::new().build_internal(
            &temp_epoch_provider,
            signer,
            credential_with_key,
            Some(mls_group_create_config.clone()),
        )?;
        let dmls_group = Self(group);

        // Move the storage from the temp new epoch to the real new epoch
        let actual_epoch = dmls_group.derive_epoch_id(provider).unwrap();
        temp_epoch_provider
            .storage()
            .clone_epoch_data(&actual_epoch)
            .unwrap();

        // Delete the old epoch storage
        temp_epoch_provider.storage().delete_epoch_data().unwrap();

        Ok(dmls_group)
    }

    /// Creates a new [`DmlsGroup`] instance from a [`StagedWelcome`].
    pub fn from_staged_welcome<Provider: OpenMlsProvider>(
        provider: &Provider,
        staged_welcome: StagedWelcome,
    ) -> Result<Self, WelcomeError<Provider::StorageError>> {
        let group = staged_welcome.into_group(provider)?;
        let dmls_group = Self(group);
        Ok(dmls_group)
    }

    /// Merge a [StagedCommit] into the group after inspection. As this advances
    /// the epoch of the group, it also clears any pending commits.
    pub fn merge_staged_commit<Provider: OpenDmlsProvider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
    ) -> Result<(), DmlsMergeError<<Provider as OpenMlsProvider>::StorageError>> {
        let old_epoch = self.derive_epoch_id(provider).unwrap();
        let old_epoch_storage = provider.storage().storage_provider_for_epoch(old_epoch);
        let temp_new_epoch = DmlsEpoch::random(provider.rand(), self.ciphersuite()).unwrap();
        // We clone the data from the old epoch storage to the new epoch
        // storage. This allows us to still process commits that are sent to the
        // old epoch. All we have to do is update the init secret of the old
        // epoch at the end to get the improved FS from the PPRF.

        // TODO: Remove unwrap
        old_epoch_storage.clone_epoch_data(&temp_new_epoch).unwrap();

        let temp_new_epoch_storage = provider
            .storage()
            .storage_provider_for_epoch(temp_new_epoch);

        let init_secret = staged_commit.init_secret().unwrap().clone();

        // All operations are now done on the new epoch storage
        self.0
            .merge_staged_commit_inner(&temp_new_epoch_storage, staged_commit)?;

        // Store the init secret of the old epoch in the old storage

        // TODO: Remove unwraps
        let mut old_epoch_secrets: GroupEpochSecrets = old_epoch_storage
            .group_epoch_secrets(self.group_id())
            .unwrap()
            .unwrap();
        old_epoch_secrets.set_init_secret(init_secret);
        old_epoch_storage
            .write_group_epoch_secrets(self.group_id(), &old_epoch_secrets)
            .unwrap();

        // Move the storage from the temp new epoch to the real new epoch
        let new_epoch = self.derive_epoch_id(provider).unwrap();
        println!("New epoch: {:?}", new_epoch);
        temp_new_epoch_storage.clone_epoch_data(&new_epoch).unwrap();
        // Delete the old epoch storage
        temp_new_epoch_storage.delete_epoch_data().unwrap();

        Ok(())
    }

    /// Merge a pending commit into the group.
    pub fn merge_pending_commit<Provider: OpenDmlsProvider>(
        &mut self,
        provider: &Provider,
    ) -> Result<(), DmlsMergePendingError<<Provider as OpenMlsProvider>::StorageError>> {
        match &self.0.group_state {
            MlsGroupState::PendingCommit(_) => {
                let old_state = mem::replace(&mut self.0.group_state, MlsGroupState::Operational);
                if let MlsGroupState::PendingCommit(pending_commit_state) = old_state {
                    self.merge_staged_commit(provider, (*pending_commit_state).into())?;
                }
                Ok(())
            }
            MlsGroupState::Inactive => Err(MlsGroupStateError::UseAfterEviction)?,
            MlsGroupState::Operational => Ok(()),
        }
    }

    /// Derive the current epoch id of this group.
    pub fn derive_epoch_id<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
    ) -> Result<DmlsEpoch, ExportSecretError> {
        let bytes = self.0.export_secret(
            provider,
            "DMLS epoch ID",
            &[],
            self.0.ciphersuite().hash_length(),
        )?;
        Ok(DmlsEpoch(bytes))
    }

    /// Returns the group state of the group with the given group id for the
    /// given epoch.
    pub fn load_for_epoch<Provider: DmlsStorageProvider>(
        storage: &Provider,
        epoch: DmlsEpoch,
        group_id: &GroupId,
    ) -> Option<Self> {
        let provider = storage.storage_provider_for_epoch(epoch);
        MlsGroup::load(&provider, group_id).unwrap().map(Self)
    }
}
