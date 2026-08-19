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
            cpi_spp_transact_signed, escrow_authority_owner_hash, u64_right_align, verify_pda,
            CreatePdaAccount,
        },
        verifier::{verify_groth16, CompressedGroth16Proof, Groth16ProofBytes},
    },
    state::{discriminator::ESCROW, load_pair_mut, Escrow},
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateEscrowIxData {
    /// `escrow_open` circuit proof (1-in: taker source UTXO / 2-out: escrow
    /// order UTXO, taker change UTXO). Taker-only: the maker's committed pool
    /// liquidity is reserved here (`liquidity_bound -= max_order_size`) and
    /// spent at settle time, so there is no funding input and no maker change;
    /// the circuit caps `owed <= max_order_size` so the reservation always
    /// covers the order.
    pub proof: Groth16ProofBytes,
    /// The taker's price limit: the escrow is rejected if the pair's current
    /// price exceeds it -- protection against an `update_price` landing between
    /// the taker building the transaction and the escrow's creation. Checked
    /// once here and discarded; it never enters a circuit or the account.
    pub max_price: u64,
    pub transact: TransactIxData,
}

/// `escrow_open`'s public-input hash: `Poseidon(PrivateTxHash,
/// EscrowAuthorityOwnerHash, SourceAsset, ExecutionPrice, MaxOrderSize)`. The
/// recipient is deliberately absent -- it is bound in-circuit to the source
/// UTXO's owner and committed as the order UTXO's DataHash, so the payout
/// destination never appears on-chain. Field order and encoding must match the
/// circuit's `PublicInputs.Check`.
pub struct EscrowOpenPublicInput<'a> {
    pub private_tx_hash: &'a [u8; 32],
    /// The escrow_authority PDA's owner-hash, recomputed on-chain (see
    /// `escrow_authority_owner_hash`); binds `OrderOut.Owner`.
    pub escrow_authority_owner_hash: &'a [u8; 32],
    /// The pair's source-asset commitment (`Pair.source_asset`); binds
    /// `SourceIn.Asset`.
    pub source_asset: &'a [u8; 32],
    /// The pair price at creation (stored as `Escrow.execution_price`); enters
    /// the circuit's `owed = order_amount * execution_price` cap.
    pub execution_price: u64,
    /// The pair's immutable `max_order_size`; the circuit enforces
    /// `owed <= max_order_size` so the reservation taken below always covers
    /// the order.
    pub max_order_size: u64,
}

impl EscrowOpenPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], ProgramError> {
        Poseidon::hashv(&[
            self.private_tx_hash.as_slice(),
            self.escrow_authority_owner_hash.as_slice(),
            self.source_asset.as_slice(),
            u64_right_align(self.execution_price).as_slice(),
            u64_right_align(self.max_order_size).as_slice(),
        ])
        .map_err(|_| DynamicSwapError::HashingFailed.into())
    }
}

/// Output order the `escrow_open` circuit commits to (exact IN1_OUT2 shape, no
/// padding): order UTXO, taker change UTXO. The program only reads the first;
/// the taker change is bound in-circuit and needs no on-chain handling.
const ORDER_OUTPUT_INDEX: usize = 0;

#[inline(never)]
#[profile]
pub fn process_create_escrow_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    // The taker signs alone: it authorizes spending its source UTXO (as the
    // transact CPI's payer, SPP's per-input signer access control) and pays the
    // escrow account rent. No maker involvement -- the maker's liquidity enters
    // at settle time.
    let taker = iter.next_signer_mut("taker")?;
    let pair_account = iter.next_mut("pair")?;
    let escrow_account = iter.next_mut("escrow")?;
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let CreateEscrowIxData {
        proof,
        max_price,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    let pair = *load_pair_mut(pair_account)?;
    let pair_address = *pair_account.address();
    let source_asset = pair.source_asset;
    // The escrow is priced at creation: snapshot the current pair price as
    // `execution_price`. A zero price would leave the escrow unpriced and
    // unsettleable, so reject it -- create_pair and update_price already forbid
    // a zero price, making this defense in depth.
    let execution_price = pair.price;
    if execution_price == 0 {
        return Err(DynamicSwapError::InvalidPrice.into());
    }
    // The taker's price limit, checked before the proof so the escrow can only
    // exist at an acceptable price; settle therefore has no refund branch.
    if execution_price > max_price {
        return Err(DynamicSwapError::MaxPriceExceeded.into());
    }
    // The worst-case reservation must be covered by committed liquidity: this
    // is the taker's hard guarantee that funds exist for the escrow's whole
    // lifetime, checked before any expensive work.
    if pair.liquidity_bound < pair.max_order_size {
        return Err(DynamicSwapError::InsufficientLiquidity.into());
    }

    // The PDA half is recomputed here (never trusted from the client), binding
    // the created order UTXO to the program-controlled escrow_authority so only
    // settle/cancel can spend it; the nullifier pubkey is the hardcoded
    // zero-secret constant.
    let escrow_authority_owner_hash = escrow_authority_owner_hash(&pair_address)?;

    // The recipient is not a public input: the circuit binds it to the taker's
    // `SourceIn.Owner` and commits it as the order UTXO's DataHash, so the
    // program never sees or passes it.
    let public_input_hash = EscrowOpenPublicInput {
        private_tx_hash: &transact.private_tx_hash,
        escrow_authority_owner_hash: &escrow_authority_owner_hash,
        source_asset: &source_asset,
        execution_price,
        max_order_size: pair.max_order_size,
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

    // `order_utxo_hash` is not read from instruction data -- it is derived here
    // directly from the transact CPI's own outputs (the proof already commits to
    // it via `private_tx_hash`), which makes a divergent client-claimed hash
    // impossible by construction.
    let order_utxo_hash = transact
        .outputs
        .get(ORDER_OUTPUT_INDEX)
        .ok_or(DynamicSwapError::InvalidInstructionData)?
        .utxo_hash;

    // The escrow account is keyed by the order UTXO's hash, so a taker can hold
    // concurrent orders and either party can derive the address from the order
    // alone.
    let escrow_bump = verify_pda(
        escrow_account.address(),
        &[Escrow::SEED_PREFIX, &order_utxo_hash],
        &crate::ID,
    )?;
    CreatePdaAccount::<2> {
        fee_payer: taker,
        new_account: escrow_account,
        space: Escrow::SIZE,
        owner: &crate::ID,
        signer_seeds: [Escrow::SEED_PREFIX, &order_utxo_hash],
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
        state.order_utxo_hash = order_utxo_hash;
        state.owner = *taker.address();
        state.created_at = Clock::get()?.slot;
        state.execution_price = execution_price;
    }

    // Take the reservation: `max_order_size` moves out of the public bound and
    // into this escrow's reservation, released by settle or cancel. The early
    // `liquidity_bound < max_order_size` check makes the subtraction safe;
    // checked ops keep it explicit.
    {
        let mut pair_mut = load_pair_mut(pair_account)?;
        pair_mut.liquidity_bound = pair_mut
            .liquidity_bound
            .checked_sub(pair_mut.max_order_size)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        pair_mut.open_reservations = pair_mut
            .open_reservations
            .checked_add(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    let transact_bytes = transact
        .serialize()
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    // The source input is authorized by the taker's outer signature (the CPI
    // payer). The escrow-authority PDA is the single flipped owner-signer,
    // authorizing the data-bearing order output.
    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(
        &pair_address,
        crate::ESCROW_AUTHORITY_PDA_SEED,
        spp_accounts,
        &transact_bytes,
    )
}
