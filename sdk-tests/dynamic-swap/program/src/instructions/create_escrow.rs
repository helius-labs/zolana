use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_hasher::{Hasher, Poseidon};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::DynamicSwapError,
    instructions::{
        shared::{
            cpi_spp_transact, escrow_authority_owner_hash, u64_right_align, verify_pda,
            CreatePdaAccount,
        },
        verifier::{verify_groth16, CompressedGroth16Proof},
    },
    state::{discriminator::ESCROW, load_pair, Escrow},
};

/// `escrow_open` circuit proof (2-in: taker source UTXO, maker funding UTXO /
/// 3-out: escrow order UTXO, reservation UTXO, maker change UTXO). No taker
/// change output: the source UTXO must match the order amount exactly -- this
/// instruction's data already sits at Solana's whole-transaction size limit with
/// a Groth16 proof, SPP's own embedded proof, and 3 real confidential outputs; a
/// 4th output would push it over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct EscrowOpenProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateEscrowIxData {
    pub proof: EscrowOpenProof,
    /// The slot the escrow's proof commits to (the same value bound into
    /// `EscrowOpenPublicInput` and the order UTXO's `DataHash`). Client-supplied
    /// and only tolerance-checked on-chain -- see `CREATED_AT_SLOT_TOLERANCE`.
    pub created_at: u64,
    pub transact: TransactIxData,
}

/// `escrow_open`'s public-input hash: `PrivateTxHash`, the escrow term visible to
/// the program (`CreatedAt`), the escrow_authority owner-hash, and the pair's two
/// asset commitments (`SourceAsset`, `DestinationAsset`). `max_price` and the
/// recipient are deliberately NOT here: both are private circuit witnesses
/// committed only into the order UTXO's `DataHash`, so neither appears on-chain.
/// Keeping `max_price` private hides the eventual settle-vs-refund outcome;
/// keeping the recipient private (bound in-circuit to the taker's `SourceIn.Owner`)
/// hides the payout destination. Field order and encoding must match the circuit's
/// `PublicInputs.Check`.
pub struct EscrowOpenPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    pub created_at: u64,
    /// The escrow_authority PDA's owner-hash, recomputed on-chain (see
    /// `escrow_authority_owner_hash`); binds `OrderOut.Owner`.
    pub escrow_authority_owner_hash: &'a [u8; 32],
    /// The pair's source-asset commitment (`Pair.source_asset`); binds
    /// `SourceIn.Asset`.
    pub source_asset: &'a [u8; 32],
    /// The pair's destination-asset commitment (`Pair.destination_asset`); binds
    /// `MakerFunding.Asset`.
    pub destination_asset: &'a [u8; 32],
}

impl EscrowOpenPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            u64_right_align(self.created_at).as_slice(),
            self.escrow_authority_owner_hash.as_slice(),
            self.source_asset.as_slice(),
            self.destination_asset.as_slice(),
        ])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
    }
}

/// Output order the `escrow_open` circuit commits to (exact IN2_OUT3 shape,
/// no padding): order UTXO, reservation UTXO, maker change UTXO. The program only
/// reads the first two; the maker change is bound in-circuit and needs no on-chain
/// handling.
const ORDER_OUTPUT_INDEX: usize = 0;
const RESERVATION_OUTPUT_INDEX: usize = 1;

/// Maximum allowed distance, in slots, between the client-supplied
/// `created_at` and the real current slot. Slots (not `unix_timestamp`) are
/// the tolerance unit because the check compares directly against
/// `Clock::get()?.slot` with no wall-clock conversion. Wide enough to absorb
/// the client's proof-generation and transaction-landing latency, tight enough
/// that a caller can't meaningfully skew the `created_at` that the order UTXO
/// and its proof commit to.
pub const CREATED_AT_SLOT_TOLERANCE: u64 = 100;

#[inline(never)]
#[profile]
pub fn process_create_escrow_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    // The pair authority (maker) signs to authorize spending its own funding UTXO
    // and pays the escrow account rent.
    let authority = iter.next_signer_mut("authority")?;
    // The source UTXO's owner (taker) must sign so only the owner can authorize
    // spending it into the escrow (SPP's per-input signer access control).
    let owner = iter.next_signer("owner")?;
    let pair_account = iter.next_account("pair")?;
    let escrow_account = iter.next_mut("escrow")?;
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let CreateEscrowIxData {
        proof,
        created_at,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = load_pair(pair_account)?;
    if &pair.authority != authority.address() {
        return Err(DynamicSwapError::Unauthorized.into());
    }
    let pair_address = *pair_account.address();
    let source_asset = pair.source_asset;
    let destination_asset = pair.destination_asset;
    // The escrow is priced at creation (commit folded in): snapshot the current
    // pair price so `execution_price` is stamped below. A zero price would leave
    // the escrow unpriced and unsettleable, so reject it -- create_pair and
    // update_price already forbid a zero price, making this defense in depth.
    let execution_price = pair.price;
    drop(pair);
    if execution_price == 0 {
        return Err(DynamicSwapError::InvalidPrice.into());
    }

    // Recomputed from the escrow_authority PDA (never trusted from the client):
    // binds the created order/reservation UTXOs to the program-controlled
    // escrow_authority so only settle can spend them.
    let escrow_authority_owner_hash = escrow_authority_owner_hash(&pair_address)?;

    // Bound the client-supplied `created_at` to the real current slot; see
    // `CREATED_AT_SLOT_TOLERANCE` for why it is client-supplied, not read here.
    let current_slot = Clock::get()?.slot;
    if current_slot.abs_diff(created_at) > CREATED_AT_SLOT_TOLERANCE {
        return Err(DynamicSwapError::CreatedAtOutOfTolerance.into());
    }

    // The recipient is not a public input: the circuit binds it to the taker's
    // `SourceIn.Owner` and commits it into the order UTXO's `DataHash`, so the
    // program never sees or passes it.
    let public_input_hash = EscrowOpenPublicInput {
        private_tx_hash: &transact.private_tx_hash,
        created_at,
        escrow_authority_owner_hash: &escrow_authority_owner_hash,
        source_asset: &source_asset,
        destination_asset: &destination_asset,
    }
    .hash()?;

    verify_groth16(
        CompressedGroth16Proof {
            a: &proof.proof_a,
            b: &proof.proof_b,
            c: &proof.proof_c,
            commitment: None,
        },
        public_input_hash,
        &crate::verifying_keys::escrow_open::VERIFYINGKEY,
    )?;

    // `escrow_utxo_hash`/`reservation_utxo_hash` are not read from instruction
    // data at all -- they're derived here directly from the transact CPI's own
    // outputs (the proof already commits to these via `private_tx_hash`), which
    // both saves 64 bytes of otherwise-redundant instruction data and makes a
    // divergent client-claimed hash impossible by construction, rather than by
    // a cross-check.
    let order_out_hash = transact
        .outputs
        .get(ORDER_OUTPUT_INDEX)
        .ok_or(DynamicSwapError::InvalidInstructionData)?
        .utxo_hash;
    let reservation_out_hash = transact
        .outputs
        .get(RESERVATION_OUTPUT_INDEX)
        .ok_or(DynamicSwapError::InvalidInstructionData)?
        .utxo_hash;

    // The escrow account is keyed by its owner (the taker), so either party can
    // derive its address from the taker's pubkey alone -- one open escrow per
    // taker at a time.
    let owner_key = *owner.address().as_array();
    let escrow_bump = verify_pda(
        escrow_account.address(),
        &[Escrow::SEED_PREFIX, &owner_key],
        &crate::ID,
    )?;
    CreatePdaAccount::<2> {
        fee_payer: authority,
        new_account: escrow_account,
        space: Escrow::SIZE,
        owner: &crate::ID,
        signer_seeds: [Escrow::SEED_PREFIX, &owner_key],
        bump: escrow_bump,
    }
    .execute()?;

    {
        let mut bytes = escrow_account
            .try_borrow_mut()
            .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
        let state: &mut Escrow = bytemuck::from_bytes_mut(&mut bytes[..]);
        state.discriminator = ESCROW;
        state.bump = escrow_bump;
        state.pair = pair_address;
        state.escrow_utxo_hash = order_out_hash;
        state.reservation_utxo_hash = reservation_out_hash;
        state.owner = *owner.address();
        state.created_at = created_at;
        state.execution_price = execution_price;
    }

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    // Both inputs are user-owned (taker's source, maker's funding), each
    // authorized by that party's own outer-transaction signature, so no PDA
    // signer is needed -- the signatures propagate into the SPP CPI.
    let spp_accounts = iter.remaining()?;
    cpi_spp_transact(spp_accounts, &transact_bytes)
}
