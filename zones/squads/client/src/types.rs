//! Backend API request/response types, mirroring the `Backend API` section of
//! `docs/squads_policy_program.md`. These are the endpoint DTOs; internally the
//! backend maps them onto the SDK's proving/construction types.

use solana_instruction::Instruction;
use solana_signature::Signature;
use zolana_squads_interface::{instruction::instruction_data::EncryptedUtxos, types::P256Pubkey};
use zolana_squads_sdk::prover::ZoneProposal;
use zolana_transaction::Address;

/// One decrypted UTXO the auditor recovered via an account's shared viewing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecryptedUtxo {
    pub utxo_hash: [u8; 32],
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; 31],
}

/// A user's balance for a single asset, decrypted with the shared viewing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetBalance {
    pub asset_id: u64,
    /// SPL mint; `Address::default()` for SOL.
    pub mint: Address,
    /// Total across the asset's UTXOs.
    pub amount: u64,
    /// The asset's UTXOs; empty when `skip_utxos`.
    pub utxos: Vec<DecryptedUtxo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetBalancesRequest {
    pub viewing_key_account: Address,
    /// When true, each `AssetBalance.utxos` is empty; `amount` is still returned.
    pub skip_utxos: bool,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetBalancesResponse {
    pub balances: Vec<AssetBalance>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetProposalsRequest {
    pub viewing_key_account: Address,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetProposalsResponse {
    pub proposals: Vec<DecryptedProposal>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecryptedProposal {
    pub pda: Address,
    /// `withdraw | transfer`.
    pub op: u8,
    pub asset_id: u64,
    pub amount: u64,
    pub recipient: Address,
    pub expiry: i64,
    pub proposal_hash: [u8; 32],
}

/// A fully reconstructed and `proposal_hash`-verified async proposal: the on-chain
/// `Proposal` identity fields, the auditor-decrypted `(amount, blinding)`, the
/// classified operation, and the [`ZoneProposal`] the settlement proof binds. The
/// crank builds one of these per pending proposal before proving and settling it.
#[derive(Clone)]
pub struct ReconstructedProposal {
    pub pda: Address,
    /// `OP_WITHDRAW` or `OP_TRANSFER`.
    pub op: u8,
    /// The sender's `owner_pk_field` (the on-chain `Proposal.owner`, equal to the
    /// sender viewing-key account's `owner`).
    pub owner: Address,
    /// The sender's raw Squads vault (the on-chain `Proposal.rent_payer`), the
    /// `owner_vault` a smart-account settlement proof spends with.
    pub sender_vault: Address,
    /// Transfer: the recipient's `owner_pk_field`. Withdrawal: `Address::default()`.
    pub recipient: Address,
    /// The asset mint (`Address::default()` for SOL).
    pub asset: Address,
    pub asset_id: u64,
    /// The decrypted operation amount (transferred, or withdrawn).
    pub amount: u64,
    /// Withdrawal: the withdrawn public amount. Transfer: `0` (nothing leaves).
    pub public_amount: u64,
    /// The decrypted 31-byte proposal blinding bound into `proposal_hash`.
    pub blinding: [u8; 31],
    pub expiry: i64,
    pub proposal_hash: [u8; 32],
    /// The proposal commitment the settlement proof binds.
    pub zone_proposal: ZoneProposal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestCreateViewingKeyAccountRequest {
    pub owner: Address,
    pub recovery_keys: Vec<P256Pubkey>,
    pub owner_signature: Option<[u8; 64]>,
    /// Owner kind written into the viewing key account: `OWNER_KIND_KEYPAIR`
    /// (P256 rail) or `OWNER_KIND_SMART_ACCOUNT` (signatureless vault rail).
    pub owner_kind: u8,
}

/// A `request*` call returns either an instruction for a smart account to wrap
/// and submit, or a signature when the backend sent the transaction for a
/// keypair owner.
#[derive(Clone, Debug)]
pub enum RequestCreateViewingKeyAccountResponse {
    /// Smart account: wrap and submit.
    Instruction {
        viewing_key_account: Address,
        instruction: Instruction,
    },
    /// Keypair: the backend sent the transaction.
    Signature {
        viewing_key_account: Address,
        signature: Signature,
    },
}

#[derive(Clone, Debug)]
pub struct RequestTransactRequest {
    pub transaction_type: TransactionType,
    pub intent: PrivateTransactionIntent,
    /// The sender's P256 owner public key. `None` selects the smart-account
    /// (signatureless) rail; `Some` selects the P256 keypair rail. The backend
    /// cannot derive it from the viewing key account (which stores only
    /// `owner_pk_field`), so the client supplies it.
    pub sender_owner_pubkey: Option<P256Pubkey>,
    /// The sender's raw Squads vault, required on the smart-account rail: the
    /// spend proof reconstructs the input owner as `hash_field(vault)`, and the
    /// viewing key account stores only that hash (its `owner`), not the vault
    /// itself, so the client supplies the preimage. `None` on the P256 rail.
    pub sender_vault: Option<Address>,
    /// The P256 owner signature `(r || s)` over `sha256(private_tx_hash)` for the
    /// keypair rail. `None` for the smart-account rail, or before the client has
    /// signed the `private_tx_hash` returned by
    /// [`SquadsBackend::request_transact_probe`](crate::SquadsBackend::request_transact_probe).
    pub owner_signature: Option<[u8; 64]>,
}

#[derive(Clone, Debug)]
pub enum RequestTransactResponse {
    /// Smart account: wrap, partial-sign, co-signer co-signs, submit.
    Instruction(Instruction),
    /// Keypair: backend co-signed and sent the transaction.
    Signature(Signature),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionType {
    Transfer {
        recipient_viewing_key_account: Address,
    },
    /// Public exit. Whether the rail is SOL or SPL is determined by the spent
    /// input's `asset_id`; the pool interface / vault is derived from it. The
    /// destination is a system account for SOL or an SPL token account for SPL.
    Withdraw {
        public_amount: u64,
        recipient_account: Address,
    },
}

/// An output UTXO the client asks the backend to create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputUtxo {
    pub owner: Address,
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; 31],
}

/// The shielded payload the client builds (it needs wallet secrets), handed to
/// the backend so it can prove and settle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTransactionIntent {
    pub sender_viewing_key_account: Address,
    pub inputs: Vec<DecryptedUtxo>,
    pub outputs: Vec<OutputUtxo>,
    pub encrypted_utxos: EncryptedUtxos,
    pub expiry: i64,
}
