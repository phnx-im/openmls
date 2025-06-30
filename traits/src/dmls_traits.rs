use std::ops::Deref;

use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{
    random::OpenMlsRand,
    storage::{StorageProvider, CURRENT_VERSION},
    types::Ciphersuite,
    OpenMlsProvider,
};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    TlsSize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
)]
pub struct DmlsEpoch(pub Vec<u8>);

impl Deref for DmlsEpoch {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DmlsEpoch {
    pub fn random<Rand: OpenMlsRand>(
        rand: &Rand,
        ciphersuite: Ciphersuite,
    ) -> Result<Self, Rand::Error> {
        let epoch = rand.random_vec(ciphersuite.hash_length())?;
        Ok(DmlsEpoch(epoch))
    }
}

pub trait DmlsStorageProvider<const VERSION: u16>: StorageProvider<VERSION> {
    /// Returns the providers epoch.
    fn epoch(&self) -> &DmlsEpoch;

    /// Returns a storage provider that serves group states for the given epoch.
    fn storage_provider_for_epoch(&self, epoch: DmlsEpoch) -> Self;

    /// Clones the data from this provider's epoch to the destination epoch.
    fn clone_epoch_data(&self, destination_epoch: &DmlsEpoch) -> Result<(), Self::Error>;

    /// Deletes the data of this provider's epoch.
    fn delete_epoch_data(&self) -> Result<(), Self::Error>;
}

pub trait OpenDmlsProvider:
    OpenMlsProvider<StorageProvider: DmlsStorageProvider<{ CURRENT_VERSION }>>
{
    fn provider_for_epoch(&self, epoch: DmlsEpoch) -> Self;
}
