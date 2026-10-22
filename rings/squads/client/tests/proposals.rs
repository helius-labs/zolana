use solana_account::Account;
use solana_keypair::Keypair;
use zolana_client::{ClientError, Rpc};
use zolana_hasher::primitives::solana_owner_identity;
use zolana_keypair::X25519Keypair;
use zolana_keypair::{hash::poseidon, X25519Pubkey};
use zolana_squads_client::{
    seed_viewing_key_account, DecryptedProposal, GetProposalsRequest, GetProposalsResponse,
    SquadsBackend, ViewingKeyAccountSeed, OP_TRANSFER, OP_WITHDRAW, SOL_ASSET_ID,
};
use zolana_squads_interface::{
    state::{Proposal, ViewingKeyAccount},
    types::Address,
};
use zolana_squads_sdk::proposal::{build_proposal_ciphertext, proposal_hash};

/// A mock RPC backed by an address -> account map; `get_program_accounts` returns
/// every stored account (all owned by the ring program in this test).
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
    shared: X25519Keypair,
    vka: ViewingKeyAccount,
}

fn seed(owner: [u8; 32], address: [u8; 32], auditor_pk: X25519Pubkey) -> SeededAccount {
    let shared = X25519Keypair::new();
    let ephemeral = X25519Keypair::new();
    let owner = Address::new_from_array(solana_owner_identity(&owner).expect("owner identity"));
    let vka = seed_viewing_key_account(
        ViewingKeyAccountSeed {
            owner,
            owner_kind: 2,
            state: 1,
            encryption_scheme: zolana_squads_interface::constants::ENCRYPTION_SCHEME_X25519_AES,
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
    auditor: X25519Keypair,
) -> SquadsBackend<MockRpc, MockRpc> {
    let indexer = MockRpc {
        accounts: Vec::new(),
    };
    let rpc = MockRpc { accounts };
    SquadsBackend::new(
        auditor,
        Keypair::new(),
        Address::default(),
        0,
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
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();

    let sender = seed([1u8; 32], [10u8; 32], auditor_pk);
    let recipient = seed([2u8; 32], [20u8; 32], auditor_pk);

    let sender_shared_pk = sender.shared.pubkey();
    let recipient_shared_pk = recipient.shared.pubkey();

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
        .reconstruct_ring_proposal(withdrawal_pda, &withdrawal)
        .expect("reconstruct withdrawal");
    assert_eq!(w.op, OP_WITHDRAW);
    assert_eq!(w.amount, withdrawn);
    assert_eq!(w.public_amount, withdrawn);
    assert_eq!(w.recipient, Address::default());
    assert_eq!(w.sender_vault, vault);
    assert_eq!(w.blinding, blinding);
    assert_eq!(w.proposal_hash, withdrawal_hash);

    let t = backend
        .reconstruct_ring_proposal(transfer_pda, &transfer)
        .expect("reconstruct transfer");
    assert_eq!(t.op, OP_TRANSFER);
    assert_eq!(t.amount, transferred);
    assert_eq!(t.public_amount, 0);
    assert_eq!(t.recipient, recipient.owner);
    assert_eq!(t.ring_proposal.recipient, owner_hash);
    assert_eq!(t.proposal_hash, transfer_hash);

    // `get_proposals` for the sender returns both (sender is a party to each).
    let response = backend
        .get_proposals(GetProposalsRequest {
            viewing_key_account: sender.address,
            signature: [0u8; 64],
        })
        .expect("get proposals");
    assert_eq!(
        response,
        GetProposalsResponse {
            proposals: vec![
                DecryptedProposal {
                    pda: withdrawal_pda,
                    op: OP_WITHDRAW,
                    asset_id: SOL_ASSET_ID,
                    amount: withdrawn,
                    recipient: Address::default(),
                    expiry: i64::MAX,
                    proposal_hash: withdrawal_hash,
                },
                DecryptedProposal {
                    pda: transfer_pda,
                    op: OP_TRANSFER,
                    asset_id: SOL_ASSET_ID,
                    amount: transferred,
                    recipient: recipient.owner,
                    expiry: i64::MAX,
                    proposal_hash: transfer_hash,
                },
            ],
        }
    );
}

/// A tampered `proposal_hash` (e.g. a wrong bound amount) must be rejected.
#[test]
fn reconstruction_rejects_hash_mismatch() {
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let sender = seed([1u8; 32], [10u8; 32], auditor_pk);
    let sender_shared_pk = sender.shared.pubkey();

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

    assert!(backend.reconstruct_ring_proposal(pda, &proposal).is_err());
}
