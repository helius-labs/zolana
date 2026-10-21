use custom_ring_interface::{
    anonymous_output_body_hash, AuditorMessage, CustomRingBasePublicInput,
    CustomRingPolicyPublicInput, DisclosureShape, RingMode, ANONYMOUS_OUTPUT_BODY_LEN,
};
use solana_address::Address;
use zolana_client::{
    prover::{
        indexed::{IndexedTransferPreparation, IndexedTransferRail},
        transact::HiddenOwnerAuthorization,
    },
    ProofInputUtxo, Shape,
};
use zolana_interface::tree_slot::populated_tree_slots_hash_chain;
use zolana_keypair::{RingAddress, ShieldedKeypair, X25519Keypair};
use zolana_ring_member_registry::MemberRegistryTree;
use zolana_ring_policy::{ListId, ListSet, Member, Rule, RuleTable, Subject};
use zolana_transaction::{instructions::transact::ConfidentialTransaction, Mint};

use super::{committed, Staged};
use crate::{
    tests::support::{account, note, pinned, ring, tree},
    witness::{
        tests::{listed, RegistryRpc},
        WitnessInput,
    },
    AnonymousPayment, AnonymousRecipient, CustomRingConfig, CustomRingTransfer,
    CustomRingTransferInput, PinnedPolicy, PoolTree,
};

const TABLE: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::Sender, ListId::Allow))
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
    .build();

/// Positions in `CustomRingBasePublicInput::elements`.
const PRIVATE_TX_HASH: usize = 0;
const TX_VIEWING_PK: [usize; 2] = [1, 2];
const AUDITOR_PK: [usize; 2] = [3, 4];
const EPH_PK: [usize; 2] = [5, 6];
const CIPHERTEXT_HASH: usize = 7;
const OUTPUT_BODY_HASHES: usize = 8;
const OUTPUT_HASHES: usize = 9;
const SALT: usize = 10;
const DISCLOSURE_HASH: usize = 11;
const ANONYMOUS: usize = 12;

fn member_of(keypair: &ShieldedKeypair) -> Member {
    Member::from_bytes(keypair.signing_pubkey().owner_proof_input_hash().unwrap()).unwrap()
}

struct Published {
    public_input_hash: [u8; 32],
    audit: [[u8; 32]; custom_ring_interface::BASE_PUBLIC_INPUT_ELEMENTS],
    policy_hash: [u8; 32],
    tree_hash: [u8; 32],
    /// `indexed_inputs` without the folded audit prefix.
    tail: Vec<[u8; 32]>,
    owner_signers: Vec<Address>,
    resolved_owner_tags: Vec<[u8; 32]>,
    output_owner_tags: Vec<Option<[u8; 32]>>,
}

async fn publish(
    sender: &ShieldedKeypair,
    recipient: &ShieldedKeypair,
    config: &CustomRingConfig,
    policy: &PinnedPolicy,
    rpc: &RegistryRpc,
) -> Published {
    let program = ring().program_id();
    let receiver = recipient.shielded_address().unwrap();
    let transaction = ConfidentialTransaction::new_with_ring(
        vec![note(sender, 10, 0, Some(program))],
        Address::new_from_array([7; 32]),
        program,
    )
    .unwrap();
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
    .with_anonymous_signer(&sender.signing_key, &sender.viewing_key)
    .with_payment(AnonymousPayment {
        to: AnonymousRecipient::Paired(RingAddress {
            recipient: receiver,
            ring_program_id: program,
            inbox_secret: recipient.viewing_key.inbox_secret(0).unwrap(),
        }),
        asset: Mint::SOL,
        amount: 4,
    })
    .unwrap()
    .with_shape(Shape::IN2_OUT2)
    .unwrap();
    let staged: Box<Staged> = transfer
        .rail
        .stage(ring(), rpc, config, None)
        .await
        .unwrap();
    let inputs = &staged.proof_inputs;
    let private_tx_hash = IndexedTransferPreparation {
        transaction: inputs.clone(),
        rail: IndexedTransferRail::AnonymousRingEddsa {
            ring: program,
            owner: HiddenOwnerAuthorization::sign(
                &sender.signing_key,
                &program,
                &inputs.message_hash().unwrap(),
            )
            .unwrap(),
            cosigner: None,
            exit_token_owner: None,
        },
    }
    .prepare_with_dummy_policy(&staged.authority, true)
    .unwrap()
    .private_tx_hash();
    let witness = WitnessInput {
        ring: ring(),
        pinned: policy,
        inputs: &inputs.input_utxos,
        outputs: &inputs.output_utxos,
        output_tree_id: inputs.output_tree_id,
        private_tx_blinding: inputs.private_tx_blinding().unwrap(),
        limits: committed(ring(), policy).unwrap(),
        key_escrow: staged.key_escrow,
    }
    .build(rpc, false)
    .await
    .unwrap();
    let shape = DisclosureShape {
        anonymous: true,
        inputs: inputs.input_utxos.len(),
        outputs: inputs.output_utxos.len(),
    };
    let message = AuditorMessage::parse(&inputs.external_data.messages[0].data, shape).unwrap();
    let output_hashes: Vec<[u8; 32]> = inputs
        .output_utxos
        .iter()
        .map(|output| {
            ProofInputUtxo::try_from((output, inputs.output_tree_id))
                .unwrap()
                .hash()
                .unwrap()
        })
        .collect();
    let output_body_hashes: Vec<[u8; 32]> = inputs
        .external_data
        .outputs
        .iter()
        .map(|output| {
            let body: [u8; ANONYMOUS_OUTPUT_BODY_LEN] =
                output.data.as_deref().unwrap()[5..].try_into().unwrap();
            anonymous_output_body_hash(&body).unwrap()
        })
        .collect();
    let proof = staged
        .pending
        .finish(private_tx_hash, witness, &policy.config.policy_hash)
        .unwrap();
    let witness = &proof.body.witness;
    let tree_slots = witness.tree_slots();
    let statement = CustomRingPolicyPublicInput {
        audit: CustomRingBasePublicInput {
            private_tx_hash: &private_tx_hash,
            tx_viewing_pk: &inputs.external_data.tx_viewing_pk,
            auditor_pk: config.auditor_pubkey.as_bytes(),
            eph_pk: message.eph_pk,
            ciphertext: message.ciphertext,
            output_body_hashes: &output_body_hashes,
            output_hashes: &output_hashes,
            salt: &inputs.external_data.salt,
            disclosure: message.disclosure,
            anonymous: true,
        },
        policy_hash: &policy.config.policy_hash,
        tree_slots: &tree_slots,
        address_tree_id: witness.address_tree_id,
        ring_id: &witness.limits.ring_id,
        namespace_owner_hash: &witness.limits.namespace_owner_hash,
        approval_required: witness.limits.approval_required,
        key_escrow: witness.key_escrow,
        member_registry_root: &witness.member_registry_root,
        foreign_root: &witness.foreign_root,
    };
    assert_eq!(statement.hash().unwrap(), proof.body.public_input_hash);
    Published {
        public_input_hash: proof.body.public_input_hash,
        audit: statement.audit.elements().unwrap(),
        policy_hash: policy.config.policy_hash,
        tree_hash: populated_tree_slots_hash_chain(&tree_slots).unwrap(),
        tail: statement.indexed_inputs().unwrap()[1..].to_vec(),
        owner_signers: staged.owner_signers.clone(),
        resolved_owner_tags: inputs.external_data.resolved_owner_tags.clone(),
        output_owner_tags: inputs
            .output_utxos
            .iter()
            .map(|output| output.owner_tag)
            .collect(),
    }
}

#[tokio::test]
async fn two_members_publish_the_same_policy_statement() {
    let alice = ShieldedKeypair::new_ed25519().unwrap();
    let bob = ShieldedKeypair::new_ed25519().unwrap();
    let recipient = ShieldedKeypair::new_ed25519().unwrap();
    let mut registry = MemberRegistryTree::new().unwrap();
    for member in [&alice, &bob, &recipient] {
        listed(
            &mut registry,
            member_of(member),
            ListSet::single(ListId::Allow),
        );
    }
    let policy = PinnedPolicy {
        config: pinned(
            ring(),
            &TABLE,
            PoolTree {
                address: tree(),
                id: 0,
            },
        ),
        table: TABLE,
    };
    let mut rpc = RegistryRpc::new(registry, None);
    rpc.accounts = std::mem::take(&mut rpc.accounts).with(
        ring().policy_config_pda(),
        account(ring().program_id(), &policy.config),
    );
    let config = CustomRingConfig {
        authority: Address::new_from_array([3; 32]),
        auditor_pubkey: X25519Keypair::new().pubkey(),
        has_policy: true,
        mode: RingMode::Anonymous,
    };
    let first = publish(&alice, &recipient, &config, &policy, &rpc).await;
    let second = publish(&bob, &recipient, &config, &policy, &rpc).await;

    assert_ne!(first.public_input_hash, second.public_input_hash);
    assert_eq!(first.policy_hash, second.policy_hash);
    assert_eq!(first.tree_hash, second.tree_hash);
    assert_eq!(first.tail, second.tail);
    assert_eq!(first.tail.len(), 7);
    let same = |index: usize| assert_eq!(first.audit[index], second.audit[index], "{index}");
    let fresh = |index: usize| assert_ne!(first.audit[index], second.audit[index], "{index}");
    AUDITOR_PK.into_iter().for_each(same);
    same(ANONYMOUS);
    // The transaction's own randomness and its openings, never a member identity in the clear.
    [
        PRIVATE_TX_HASH,
        CIPHERTEXT_HASH,
        OUTPUT_BODY_HASHES,
        OUTPUT_HASHES,
        SALT,
        DISCLOSURE_HASH,
    ]
    .into_iter()
    .chain(TX_VIEWING_PK)
    .chain(EPH_PK)
    .for_each(fresh);

    for (published, member) in [(&first, &alice), (&second, &bob)] {
        assert!(published.owner_signers.is_empty());
        assert!(published
            .output_owner_tags
            .iter()
            .all(|tag| *tag == Some([0; 32])));
        let signing_key = member.signing_pubkey().as_ed25519().unwrap();
        let owner_hash = member.signing_pubkey().owner_proof_input_hash().unwrap();
        assert!(!published
            .resolved_owner_tags
            .iter()
            .any(|tag| *tag == signing_key || *tag == owner_hash));
    }
}
