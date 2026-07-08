use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_account::Account;
use solana_keypair::Keypair;
use zolana_client::{ClientError, Rpc};
use zolana_keypair::{hash::poseidon, P256Pubkey};
use zolana_squads_client::{
    seed_viewing_key_account, GetProposalsRequest, SquadsBackend, ViewingKeyAccountSeed,
    OP_TRANSFER, OP_WITHDRAW,
};
use zolana_squads_interface::{
    state::{Proposal, ViewingKeyAccount},
    types::Address,
};
use zolana_squads_sdk::proposal::{build_proposal_ciphertext, proposal_hash};

/// A mock RPC backed by an address -> account map; `get_program_accounts` returns
/// every stored account (all owned by the zone program in this test).
struct MockRpc {
    accounts: Vec<(Address, Account)>,
}

impl MockRpc {
    fn account(data: Vec<u8>) -> Account {
        Account {
            lamports: 1,
            data,
            owner: Address::default(),
            executable: false,
            rent_epoch: 0,
        }
    }
}

impl Rpc for MockRpc {
    fn get_account(&self, address: Address) -> core::result::Result<Option<Account>, ClientError> {
        Ok(self
            .accounts
            .iter()
            .find(|(a, _)| *a == address)
            .map(|(_, acc)| acc.clone()))
    }

    fn get_program_accounts(
        &self,
        _program_id: Address,
    ) -> core::result::Result<Vec<(Address, Account)>, ClientError> {
        Ok(self.accounts.clone())
    }
}

struct SeededAccount {
    address: Address,
    owner: Address,
    shared: SecretKey,
    vka: ViewingKeyAccount,
}

fn seed(owner: [u8; 32], address: [u8; 32], auditor_pk: P256Pubkey) -> SeededAccount {
    let shared = SecretKey::random(&mut OsRng);
    let ephemeral = SecretKey::random(&mut OsRng);
    let owner = Address::new_from_array(owner);
    let vka = seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner,
            owner_kind: 2,
            state: 1,
            encryption_scheme: 0,
            key_nonce: 0,
        },
        &shared,
        &ephemeral,
        &[3u8; 32],
        &[],
        &[auditor_pk],
    )
    .expect("seed account");
    SeededAccount {
        address: Address::new_from_array(address),
        owner,
        shared,
        vka,
    }
}

fn build_backend(
    accounts: Vec<(Address, Account)>,
    auditor: SecretKey,
) -> SquadsBackend<MockRpc, MockRpc> {
    let indexer = MockRpc {
        accounts: Vec::new(),
    };
    let rpc = MockRpc { accounts };
    SquadsBackend::new(
        auditor,
        Keypair::new(),
        Address::default(),
        Address::default(),
        "http://127.0.0.1:3001",
        indexer,
        rpc,
    )
}

/// A withdrawal proposal (recipient == 0) is encrypted to the sender; a transfer
/// proposal (recipient != 0) is encrypted to the recipient. `get_proposals` (and
/// the reconstruction helper) must resolve the correct viewing key account, decrypt,
/// classify, and verify each against the on-chain `proposal_hash`.
#[test]
fn reconstructs_and_classifies_withdrawal_and_transfer() {
    let auditor = SecretKey::random(&mut OsRng);
    let auditor_pk = P256Pubkey::from_p256(&auditor.public_key());

    let sender = seed([1u8; 32], [10u8; 32], auditor_pk);
    let recipient = seed([2u8; 32], [20u8; 32], auditor_pk);

    let sender_shared_pk = P256Pubkey::from_p256(&sender.shared.public_key());
    let recipient_shared_pk = P256Pubkey::from_p256(&recipient.shared.public_key());

    let vault = Address::new_from_array([99u8; 32]);
    let blinding = [7u8; 31];
    let withdrawn = 2_000_000_000u64;
    let transferred = 1_000_000_000u64;

    // Withdrawal: recipient == 0, encrypted to the sender, public_amount == amount.
    let withdrawal_hash = proposal_hash(0, &[0u8; 32], &blinding, withdrawn).expect("hash");
    let withdrawal_ct =
        build_proposal_ciphertext(withdrawn, &blinding, &sender_shared_pk, &[5u8; 32]).expect("ct");
    let withdrawal = Proposal::new(
        sender.owner,
        Address::default(),
        Address::default(),
        withdrawal_hash,
        withdrawal_ct,
        i64::MAX,
        vault,
    );
    let withdrawal_pda = Address::new_from_array([30u8; 32]);

    // Transfer: recipient == recipient owner_pk_field, encrypted to the recipient,
    // proposal recipient bound as Poseidon(owner_pk_field, nullifier_pubkey).
    let owner_hash = poseidon(&[
        recipient.owner.to_bytes().as_ref(),
        recipient.vka.nullifier_pubkey.as_ref(),
    ])
    .expect("owner hash");
    let transfer_hash = proposal_hash(transferred, &owner_hash, &blinding, 0).expect("hash");
    let transfer_ct =
        build_proposal_ciphertext(transferred, &blinding, &recipient_shared_pk, &[6u8; 32])
            .expect("ct");
    let transfer = Proposal::new(
        sender.owner,
        recipient.owner,
        Address::default(),
        transfer_hash,
        transfer_ct,
        i64::MAX,
        vault,
    );
    let transfer_pda = Address::new_from_array([31u8; 32]);

    let accounts = vec![
        (
            sender.address,
            MockRpc::account(sender.vka.serialize().expect("vka")),
        ),
        (
            recipient.address,
            MockRpc::account(recipient.vka.serialize().expect("vka")),
        ),
        (
            withdrawal_pda,
            MockRpc::account(withdrawal.serialize().expect("proposal")),
        ),
        (
            transfer_pda,
            MockRpc::account(transfer.serialize().expect("proposal")),
        ),
    ];
    let backend = build_backend(accounts, auditor);

    // Direct reconstruction: fields + hash verification.
    let w = backend
        .reconstruct_zone_proposal(withdrawal_pda, &withdrawal)
        .expect("reconstruct withdrawal");
    assert_eq!(w.op, OP_WITHDRAW);
    assert_eq!(w.amount, withdrawn);
    assert_eq!(w.public_amount, withdrawn);
    assert_eq!(w.recipient, Address::default());
    assert_eq!(w.sender_vault, vault);
    assert_eq!(w.blinding, blinding);
    assert_eq!(w.proposal_hash, withdrawal_hash);

    let t = backend
        .reconstruct_zone_proposal(transfer_pda, &transfer)
        .expect("reconstruct transfer");
    assert_eq!(t.op, OP_TRANSFER);
    assert_eq!(t.amount, transferred);
    assert_eq!(t.public_amount, 0);
    assert_eq!(t.recipient, recipient.owner);
    assert_eq!(t.zone_proposal.recipient, owner_hash);
    assert_eq!(t.proposal_hash, transfer_hash);

    // `get_proposals` for the sender returns both (sender is a party to each).
    let response = backend
        .get_proposals(GetProposalsRequest {
            viewing_key_account: sender.address,
            signature: [0u8; 64],
        })
        .expect("get proposals");
    assert_eq!(response.proposals.len(), 2);
    let withdrawal_out = response
        .proposals
        .iter()
        .find(|p| p.op == OP_WITHDRAW)
        .expect("withdrawal proposal");
    assert_eq!(withdrawal_out.pda, withdrawal_pda);
    assert_eq!(withdrawal_out.amount, withdrawn);
    let transfer_out = response
        .proposals
        .iter()
        .find(|p| p.op == OP_TRANSFER)
        .expect("transfer proposal");
    assert_eq!(transfer_out.pda, transfer_pda);
    assert_eq!(transfer_out.amount, transferred);
    assert_eq!(transfer_out.recipient, recipient.owner);
}

/// A tampered `proposal_hash` (e.g. a wrong bound amount) must be rejected.
#[test]
fn reconstruction_rejects_hash_mismatch() {
    let auditor = SecretKey::random(&mut OsRng);
    let auditor_pk = P256Pubkey::from_p256(&auditor.public_key());
    let sender = seed([1u8; 32], [10u8; 32], auditor_pk);
    let sender_shared_pk = P256Pubkey::from_p256(&sender.shared.public_key());

    let blinding = [7u8; 31];
    let ct = build_proposal_ciphertext(500, &blinding, &sender_shared_pk, &[5u8; 32]).expect("ct");
    // Hash bound to a different withdrawn amount than the ciphertext carries.
    let wrong_hash = proposal_hash(0, &[0u8; 32], &blinding, 999).expect("hash");
    let proposal = Proposal::new(
        sender.owner,
        Address::default(),
        Address::default(),
        wrong_hash,
        ct,
        i64::MAX,
        Address::new_from_array([99u8; 32]),
    );
    let pda = Address::new_from_array([30u8; 32]);

    let accounts = vec![
        (
            sender.address,
            MockRpc::account(sender.vka.serialize().expect("vka")),
        ),
        (
            pda,
            MockRpc::account(proposal.serialize().expect("proposal")),
        ),
    ];
    let backend = build_backend(accounts, auditor);

    assert!(backend.reconstruct_zone_proposal(pda, &proposal).is_err());
}
