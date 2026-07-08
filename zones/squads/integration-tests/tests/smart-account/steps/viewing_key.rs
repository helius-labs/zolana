//! `{word} has a viewing key account`: create the account at RUNTIME through the
//! backend (`request_create_viewing_key_account`), which mints RANDOM viewing /
//! nullifier secrets recoverable only via the auditor key and lands the account at
//! the canonical `find_program_address([VIEWING_KEY_ACCOUNT_PDA_SEED, owner])` PDA.
//!
//! The vault sender is created with `OWNER_KIND_SMART_ACCOUNT`, P256 recipients with
//! `OWNER_KIND_KEYPAIR`. Both are auditor-only (no recovery keys, no owner
//! signature), so the program requires no owner signer; the backend sets the new
//! account's rent-payer (`fee_payer`) to its relayer (the zone co-signer), which is
//! therefore the only required signer.

use anyhow::{anyhow, Result};
use cucumber::given;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_squads_client::{
    RequestCreateViewingKeyAccountRequest, RequestCreateViewingKeyAccountResponse,
};
use zolana_squads_interface::constants::{OWNER_KIND_KEYPAIR, OWNER_KIND_SMART_ACCOUNT};

use crate::{
    fixture::{is_vault_sender, owner_field, viewing_key_account_pda},
    localnet::send_transaction,
    SquadsLifecycleWorld,
};

impl SquadsLifecycleWorld {
    /// The canonical viewing-key-account PDA for `name`.
    pub(crate) fn viewing_key_account_address(&self, name: &str) -> Address {
        Address::new_from_array(viewing_key_account_pda(name).to_bytes())
    }

    /// Create `name`'s viewing key account through the backend if it does not exist.
    /// All vault-sender names share one VKA (owner = vault owner field), so a
    /// second vault-sender in the same scenario reuses the existing account.
    pub(crate) fn ensure_viewing_key_account(&mut self, name: &str) -> Result<()> {
        let address = self.viewing_key_account_address(name);
        if self.rpc.get_account(address)?.is_some() {
            return Ok(());
        }

        let owner_kind = if is_vault_sender(name) {
            OWNER_KIND_SMART_ACCOUNT
        } else {
            OWNER_KIND_KEYPAIR
        };
        let response = self
            .backend
            .request_create_viewing_key_account(RequestCreateViewingKeyAccountRequest {
                owner: Address::new_from_array(owner_field(name)),
                recovery_keys: Vec::new(),
                owner_signature: None,
                owner_kind,
            })
            .map_err(|e| anyhow!("backend request_create_viewing_key_account: {e}"))?;

        let instruction = match response {
            RequestCreateViewingKeyAccountResponse::Instruction { instruction, .. } => instruction,
            RequestCreateViewingKeyAccountResponse::Signature { .. } => return Ok(()),
        };

        // The key-encryption proof verification exceeds the default 200k CU budget.
        let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let payer = self.payer.insecure_clone();
        let co_signer = self.co_signer.insecure_clone();
        send_transaction(
            &mut self.rpc,
            &[budget, instruction],
            &payer.pubkey(),
            &[&payer, &co_signer],
        )?;
        Ok(())
    }
}

#[given(expr = "{word} has a viewing key account")]
fn has_viewing_key_account(world: &mut SquadsLifecycleWorld, name: String) {
    world
        .ensure_viewing_key_account(&name)
        .expect("create viewing key account");
}
