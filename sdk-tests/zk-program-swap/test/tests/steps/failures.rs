use anyhow::Result;
use cucumber::then;
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use swap_sdk::{CancelProof, FillVerifiableEncryptionProof};
use zolana_interface::{
    instruction::instruction_data::transact::{OutputCiphertext, TransactIxData, TransactProof},
    SHIELDED_POOL_PROGRAM_ID,
};

use crate::{localnet::send_transaction, steps::assert_custom_error, SwapWorld};

const EXPIRED: u32 = 8005;
const NOT_YET_EXPIRED: u32 = 8006;
const PROOF_VERIFICATION_FAILED: u32 = 8007;

const PAST_EXPIRY: u64 = 1;
const FUTURE_EXPIRY: u64 = 4_000_000_000;

/// A structurally valid but empty `transact` body. The negative scenarios fail
/// in the swap program before the SPP CPI, so the transact body only needs to parse:
/// the swap guards read `expiry_unix_ts` (the order expiry) and, for the proof path,
/// the tail `output_ciphertexts` slot whose `ctHash` the fill proof commits.
fn dummy_transact(expiry_unix_ts: u64, with_ciphertext: bool) -> TransactIxData {
    let output_ciphertexts = if with_ciphertext {
        vec![OutputCiphertext {
            view_tag: [0u8; 32],
            data: vec![0u8; 32],
        }]
    } else {
        Vec::new()
    };
    TransactIxData {
        expiry_unix_ts,
        relayer_fee: 0,
        private_tx_hash: [0u8; 32],
        p256_signing_pk_field: None,
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        proof: TransactProof::zeroed_eddsa(),
        inputs: Vec::new(),
        public_sol_amount: None,
        public_spl_amount: None,
        data_hash: None,
        zone_data_hash: None,
        output_utxo_hashes: Vec::new(),
        output_ciphertexts,
    }
}

fn zeroed_fill_proof() -> FillVerifiableEncryptionProof {
    FillVerifiableEncryptionProof {
        proof_a: [0u8; 32],
        proof_b: [0u8; 64],
        proof_c: [0u8; 32],
        commitment: [0u8; 32],
        commitment_pok: [0u8; 32],
    }
}

fn zeroed_cancel_proof() -> CancelProof {
    CancelProof {
        proof_a: [0u8; 32],
        proof_b: [0u8; 64],
        proof_c: [0u8; 32],
    }
}

fn spp_program_id() -> Pubkey {
    Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
}

impl SwapWorld {
    fn try_fill(&mut self, expiry_unix_ts: u64, with_ciphertext: bool) -> Result<()> {
        let taker = Keypair::new();
        self.rpc.airdrop(&taker.pubkey(), 1_000_000_000)?;

        let spp_accounts = vec![
            AccountMeta::new(taker.pubkey(), true),
            AccountMeta::new(self.tree, false),
            AccountMeta::new_readonly(swap_sdk::escrow_authority_pda(), false),
            AccountMeta::new_readonly(spp_program_id(), false),
        ];
        let ix = swap_sdk::fill_verifiable_encryption(
            taker.pubkey(),
            spp_accounts,
            zeroed_fill_proof(),
            dummy_transact(expiry_unix_ts, with_ciphertext),
        );
        send_transaction(&mut self.rpc, &[ix], &taker.pubkey(), &[&taker])?;
        Ok(())
    }

    fn try_cancel(&mut self, order_expiry: u64) -> Result<()> {
        let caller = Keypair::new();
        self.rpc.airdrop(&caller.pubkey(), 1_000_000_000)?;

        let spp_accounts = vec![
            AccountMeta::new(caller.pubkey(), true),
            AccountMeta::new(self.tree, false),
            AccountMeta::new_readonly(swap_sdk::escrow_authority_pda(), false),
            AccountMeta::new_readonly(spp_program_id(), false),
        ];
        let ix = swap_sdk::cancel(
            caller.pubkey(),
            caller.pubkey(),
            spp_accounts,
            zeroed_cancel_proof(),
            order_expiry,
            dummy_transact(FUTURE_EXPIRY, false),
        );
        send_transaction(&mut self.rpc, &[ix], &caller.pubkey(), &[&caller])?;
        Ok(())
    }
}

#[then(expr = "a fill after the order expiry is rejected as expired")]
fn fill_after_expiry_rejected(world: &mut SwapWorld) {
    match world.try_fill(PAST_EXPIRY, false) {
        Ok(()) => panic!("fill after expiry unexpectedly succeeded"),
        Err(error) => assert_custom_error(&error, EXPIRED),
    }
}

#[then(expr = "a cancel before the order expiry is rejected as not yet expired")]
fn cancel_before_expiry_rejected(world: &mut SwapWorld) {
    match world.try_cancel(FUTURE_EXPIRY) {
        Ok(()) => panic!("cancel before expiry unexpectedly succeeded"),
        Err(error) => assert_custom_error(&error, NOT_YET_EXPIRED),
    }
}

#[then(expr = "a fill carrying an invalid order proof is rejected")]
fn fill_invalid_proof_rejected(world: &mut SwapWorld) {
    match world.try_fill(FUTURE_EXPIRY, true) {
        Ok(()) => panic!("fill with an invalid proof unexpectedly succeeded"),
        Err(error) => assert_custom_error(&error, PROOF_VERIFICATION_FAILED),
    }
}
