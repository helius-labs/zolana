use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::DynamicSwapError,
    instructions::{
        shared::{
            cpi_spp_transact_signed, escrow_authority_owner_hash, verify_pda, CreatePdaAccount,
        },
        verifier::Groth16ProofBytes,
    },
    state::{discriminator::ESCROW, load_pair_mut, Escrow},
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateEscrowIxData {
    /// `escrow_open` circuit proof (1-in: taker source UTXO / 2-out: escrow
    /// order UTXO, taker change UTXO). Taker-only: the maker's committed pool
    /// liquidity is reserved here (`available_liquidity -= max_order_size`) and
    /// spent at settle time, so there is no funding input and no maker change;
    /// the circuit caps `owed <= max_order_size` so the reservation always
    /// covers the order.
    pub proof: Groth16ProofBytes,
    /// Public lower edge `F` of the accepted price window. With the pair's
    /// immutable tolerance `X`, the live price must be in `[F, F + 2X]`.
    pub public_price_floor: u64,
    pub transact: TransactIxData,
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
        public_price_floor,
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
    // The public floor is range-limited by the pair's immutable absolute
    // tolerance. The proof uses the same upper edge as its worst-case payout,
    // so accepting outside the range would under-collateralize the reservation.
    let doubled_tolerance = pair
        .price_tolerance
        .checked_mul(2)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let coverage_price = public_price_floor
        .checked_add(doubled_tolerance)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if execution_price < public_price_floor || execution_price > coverage_price {
        return Err(DynamicSwapError::PublicPriceFloorOutOfRange.into());
    }
    // The worst-case reservation must be covered by committed liquidity: this
    // is the taker's hard guarantee that funds exist for the escrow's whole
    // lifetime, checked before any expensive work.
    if pair.available_liquidity < pair.max_order_size {
        return Err(DynamicSwapError::InsufficientLiquidity.into());
    }

    // Fix a resolvable deadline before accepting funds or creating the account.
    // Resolution never recomputes this sum, so every accepted order has an
    // expiry representable in the Clock's slot type.
    let next_order_id = pair
        .next_order_id
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let expires_at = Clock::get()?
        .slot
        .checked_add(pair.expiry_slots)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // A competing creation consumes this id. Reject its stale PDA before
    // proof verification; the same proof can be retried with the new id.
    let order_id = pair.next_order_id;
    let order_id_seed = order_id.to_le_bytes();
    let escrow_bump = verify_pda(
        escrow_account.address(),
        &[Escrow::SEED_PREFIX, pair_address.as_array(), &order_id_seed],
        &crate::ID,
    )?;

    // The PDA half is recomputed here (never trusted from the client), binding
    // the created order UTXO to the program-controlled escrow_authority so only
    // settle/cancel can spend it; the nullifier pubkey is the hardcoded
    // zero-secret constant.
    let escrow_authority_owner_hash = escrow_authority_owner_hash(&pair_address)?;

    // The recipient and minimum price are not public inputs: the circuit binds
    // the recipient to the taker's `SourceIn.Owner` and commits both private
    // values as the order UTXO's DataHash, so the program never sees them.
    crate::verifier::escrow_open::Verifier {
        proof: &proof.to_compressed(),
        public_inputs: crate::verifier::escrow_open::PublicInputs {
            escrow_authority_owner_hash,
            source_asset,
            public_price_floor,
            price_tolerance: pair.price_tolerance,
            min_order_amount: pair.min_order_amount,
            max_order_size: pair.max_order_size,
        },
        private_tx_hash: &transact.private_tx_hash,
        transfers: &[],
    }
    .verify()
    .map_err(|_| DynamicSwapError::ProofVerificationFailed)?;

    // `order_utxo_hash` is not read from instruction data -- it is derived here
    // directly from the transact CPI's own outputs (the proof already commits to
    // it via `private_tx_hash`), which makes a divergent client-claimed hash
    // impossible by construction.
    let order_utxo_hash = transact
        .outputs
        .get(ORDER_OUTPUT_INDEX)
        .ok_or(DynamicSwapError::InvalidInstructionData)?
        .utxo_hash;

    // The order joins the pair's FIFO queue at `next_order_id`, and the escrow
    // account is keyed by the pair and that position, so either party can
    // derive the head order's address from the pair alone. A taker racing
    // another create_escrow rebuilds the instruction for the next id; the
    // proof does not depend on it.
    CreatePdaAccount::<3> {
        fee_payer: taker,
        new_account: escrow_account,
        space: Escrow::SIZE,
        owner: &crate::ID,
        signer_seeds: [Escrow::SEED_PREFIX, pair_address.as_array(), &order_id_seed],
        bump: escrow_bump,
    }
    .execute()?;

    {
        let mut bytes = escrow_account
            .try_borrow_mut()
            .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
        let state: &mut Escrow = bytemuck::from_bytes_mut(&mut bytes[..]);
        *state = Escrow {
            discriminator: ESCROW,
            bump: escrow_bump,
            cancelled: 0,
            _pad: [0; 5],
            pair: pair_address,
            order_utxo_hash,
            owner: *taker.address(),
            expires_at,
            execution_price,
            order_id,
        };
    }

    // Take the reservation: `max_order_size` moves out of the public bound and
    // into this escrow's reservation, released by settle or cancel. The early
    // `available_liquidity < max_order_size` check makes the subtraction safe;
    // checked ops keep it explicit.
    {
        let mut pair_mut = load_pair_mut(pair_account)?;
        pair_mut.available_liquidity = pair_mut
            .available_liquidity
            .checked_sub(pair_mut.max_order_size)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        pair_mut.open_reservations = pair_mut
            .open_reservations
            .checked_add(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        pair_mut.next_order_id = next_order_id;
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
