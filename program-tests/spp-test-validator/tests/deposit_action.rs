//! Proofless shield (deposit) action used by the lifecycle steps.
//!
//! The client SDK exposes the lower-level `actions::Deposit` builder; this test
//! crate keeps the higher-level sender-driven `Deposit` (which detects SOL vs
//! SPL from the funding account) local to the tests that exercise it.

use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ClientError, Rpc};
use zolana_interface::{
    instruction::{Deposit as DepositInstruction, DepositIxData, DepositSplAccounts},
    pda,
};
use zolana_keypair::{random_blinding, ShieldedAddress};
use zolana_transaction::{Data, Utxo, SOL_MINT};

/// Outcome of a shield: the on-chain signature and the created note, ready to
/// spend (and re-discoverable by `Wallet::sync` from the deposit's `owner`).
#[derive(Clone, Debug)]
pub struct DepositResult {
    pub signature: Signature,
    pub utxo: Utxo,
    /// The instruction data that was sent, for asserting the indexed deposit.
    pub data: DepositIxData,
}

/// A direct (non-zone) proofless shield that appends a recipient-hidden,
/// wallet-discoverable UTXO.
///
/// The asset is inferred from `sender`: a system-owned account shields SOL; an
/// SPL token account shields its mint, with the mint, vault and registry PDAs,
/// and owning token program all derived from it. The caller passes none of them.
///
/// The recipient is identified by its public [`ShieldedAddress`] only, so a
/// depositor can shield to a third party without holding any of its secrets.
pub struct Deposit<'a> {
    /// State tree the deposit appends to.
    pub tree: Pubkey,
    /// Public shielded identity the note becomes spendable by and discoverable for.
    pub recipient: &'a ShieldedAddress,
    /// Funding account: a SOL system account or an SPL token account. The asset
    /// (and, for SPL, the mint/vault/registry/token-program) is detected from it.
    pub sender: Pubkey,
    /// Public amount to shield (lamports for SOL, base units for SPL).
    pub amount: u64,
}

impl Deposit<'_> {
    /// Build and send the shield. `payer` funds the fee; `authority` signs the
    /// debit of `sender` (for SOL it must equal `sender`; for SPL it is the token
    /// account's owner).
    pub fn execute<R: Rpc>(
        self,
        rpc: &R,
        payer: &Keypair,
        authority: &Keypair,
    ) -> Result<DepositResult, ClientError> {
        // The recipient `owner_hash` is computed from public address material and
        // a fresh blinding is sent in the clear, so the depositor needs no shared
        // secret; the recipient re-derives the note from the deposit event.
        let owner = self.recipient.owner_hash()?;
        let blinding = random_blinding();
        let view_tag = self.recipient.viewing_pubkey.x();

        let sender_account = rpc.get_account(Address::new_from_array(self.sender.to_bytes()))?;
        let system_owned = sender_account
            .as_ref()
            .map(|account| account.owner == Pubkey::new_from_array([0u8; 32]))
            .unwrap_or(true);

        let (asset, spl_accounts) = if system_owned {
            // SOL: the funding system account must itself sign the debit.
            if self.sender != authority.pubkey() {
                return Err(ClientError::DepositSenderNotSigner {
                    sender: self.sender.to_bytes(),
                });
            }
            (SOL_MINT, None)
        } else {
            // SPL: `sender` is a token account; everything else derives from it.
            let account = sender_account.ok_or(ClientError::AccountNotFound {
                address: self.sender.to_bytes(),
            })?;
            let mint_bytes: [u8; 32] = account
                .data
                .get(0..32)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(ClientError::AccountNotFound {
                    address: self.sender.to_bytes(),
                })?;
            let mint = Pubkey::new_from_array(mint_bytes);
            (
                Address::new_from_array(mint_bytes),
                Some(DepositSplAccounts {
                    user_token: self.sender,
                    vault: pda::spl_asset_vault(&mint),
                    registry: pda::spl_asset_registry(&mint),
                    token_program: account.owner,
                }),
            )
        };

        let data = DepositIxData {
            view_tag,
            owner,
            blinding,
            public_amount: Some(self.amount),
            utxo_data: None,
            memo: None,
        };
        let ix = DepositInstruction {
            tree: self.tree,
            depositor: authority.pubkey(),
            spl: spl_accounts,
            view_tag: data.view_tag,
            owner: data.owner,
            blinding: data.blinding,
            public_amount: data.public_amount,
            utxo_data: data.utxo_data.clone(),
            memo: data.memo.clone(),
        }
        .instruction();
        let mut signers: Vec<&Keypair> = vec![payer];
        if authority.pubkey() != payer.pubkey() {
            signers.push(authority);
        }
        let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
        let signature = rpc.create_and_send_transaction(&[ix], payer_address, &signers)?;
        let utxo = Utxo {
            owner: self.recipient.signing_pubkey,
            asset,
            amount: self.amount,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        Ok(DepositResult {
            signature,
            utxo,
            data,
        })
    }
}
