use openmls::{
    group::{
        dmls::{
            dmls_group::DmlsGroup, dmls_message::DmlsMessageIn, wrappers::ProcessDmlsMessageError,
        },
        MlsGroupCreateConfig, MlsGroupJoinConfig, ProcessMessageError, StagedWelcome,
    },
    prelude::{
        test_utils::new_credential, Ciphersuite, CredentialWithKey, KeyPackage, LeafNodeParameters,
        ProcessedMessageContent,
    },
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::opendmls_test;
use openmls_traits::dmls_traits::OpenDmlsProvider;
use tls_codec::{Deserialize as _, Serialize};

pub fn create_alice_group(
    ciphersuite: Ciphersuite,
    provider: &impl OpenDmlsProvider,
    use_ratchet_tree_extension: bool,
) -> (DmlsGroup, CredentialWithKey, SignatureKeyPair) {
    let group_config = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(use_ratchet_tree_extension)
        .ciphersuite(ciphersuite)
        .build();

    let (credential_with_key, signature_keys) =
        new_credential(provider, b"Alice", ciphersuite.signature_algorithm());

    println!("Creating group");
    let group = DmlsGroup::new(
        provider,
        &signature_keys,
        &group_config,
        credential_with_key.clone(),
    )
    .expect("An unexpected error occurred.");
    println!("");

    (group, credential_with_key, signature_keys)
}

#[opendmls_test]
fn cant_process_same_commit_twice() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

    let alice_provider = Provider::default();
    let (mut alice_group, _alice_credential, alice_signer) =
        create_alice_group(ciphersuite, &alice_provider, true);

    let bob_provider = Provider::default();
    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());

    let bob_kpb = KeyPackage::builder()
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .unwrap();

    // Alice invites Bob to her group.
    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            &[bob_kpb.key_package().clone()],
        )
        .unwrap();

    alice_group.merge_pending_commit(&alice_provider).unwrap();
    let epoch_id = alice_group.derive_epoch_id(&alice_provider).unwrap();

    let group_config = MlsGroupJoinConfig::builder().build();

    let bob_staged_welcome = StagedWelcome::new_from_welcome(
        &bob_provider,
        &group_config,
        welcome.into_welcome().unwrap(),
        None,
    )
    .unwrap();

    let mut bob_group = DmlsGroup::from_staged_welcome(&bob_provider, bob_staged_welcome).unwrap();

    // Bob does a self-update
    let first_commit_result = bob_group
        .self_update(&bob_provider, &bob_signer, LeafNodeParameters::default())
        .unwrap();

    let dmls_message_bytes = first_commit_result
        .dmls_message
        .tls_serialize_detached()
        .unwrap();
    let dmls_message = DmlsMessageIn::tls_deserialize_exact(dmls_message_bytes.as_slice()).unwrap();

    // Alice processes Bob's commit
    let processed_message = alice_group
        .process_message(&alice_provider, dmls_message.clone())
        .unwrap();

    // Alice merges the commit
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    else {
        panic!("Expected a staged commit message");
    };

    alice_group
        .merge_staged_commit(&alice_provider, *staged_commit)
        .unwrap();

    // We now go back to the group state from before Alice merged the commit

    // We should be able to load the group for the epoch before the commit
    let mut alice_old_group = DmlsGroup::load_for_epoch(
        alice_provider.storage(),
        epoch_id.clone(),
        alice_group.group_id(),
    )
    .unwrap();

    // Processing the same commit twice should fail, becacuse the init secret
    // was already punctured.
    let err = alice_old_group
        .process_message(&alice_provider, dmls_message)
        .unwrap_err();

    // TODO: This shouldn't return a LibraryError, but a more specific error
    assert!(matches!(
        err,
        ProcessDmlsMessageError::ProcessMessageError(ProcessMessageError::InvalidCommit(
            openmls::group::StageCommitError::LibraryError(_)
        ))
    ));

    // Bob deletes his pending commit and creates a new one
    bob_group.clear_pending_commit(&bob_provider).unwrap();

    let second_commit_result = bob_group
        .self_update(&bob_provider, &bob_signer, LeafNodeParameters::default())
        .unwrap();

    let dmls_message_bytes = second_commit_result
        .dmls_message
        .tls_serialize_detached()
        .unwrap();
    let dmls_message = DmlsMessageIn::tls_deserialize_exact(dmls_message_bytes.as_slice()).unwrap();

    // Alice processes Bob's second commit
    let processed_message = alice_old_group
        .process_message(&alice_provider, dmls_message.clone())
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    else {
        panic!("Expected a staged commit message");
    };
    alice_old_group
        .merge_staged_commit(&alice_provider, *staged_commit)
        .unwrap();
}
