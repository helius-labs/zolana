use custom_ring_program::instructions::transact::{AuditProof, CustomRingTransactIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::instruction::{
    RingTransact, TransactInterfaceTransferAccounts, TransactIxData,
};

use crate::{config_pda, tag, PROGRAM_ID};

/// Audited ring transact: the ring's auditor key-encryption proof followed by the
/// SPP payload it forwards.
///
/// The account list is `[payer, config, approval?]` prepended to SPP's own
/// `RING_TRANSACT` list. Those extra accounts are all this program reads for
/// itself, the payer it requires as a signer, the config account holding the
/// auditor key the public-input hash is recomputed against and the policy, and
/// the approval account a withdrawal under an approval rule spends. Everything
/// after them is forwarded to SPP position for position, so it is taken straight from
/// [`RingTransact::instruction`] rather than re-listed here -- a hand-written copy
/// would be a second definition of SPP's loader order, free to drift from it.
///
/// `ring_config` (this program's `ring_auth` PDA) stays unsigned: no keypair
/// exists for it, and the program is what flips the meta to a signer inside its
/// CPI. Marking it a signer here would make the transaction unsignable.
pub struct RingTransactWithAudit {
    pub payer: Address,
    pub input_tree: Address,
    pub output_tree: Address,
    /// The eddsa owners of the spent UTXOs; SPP requires each as a signer.
    pub owner_signers: Vec<Address>,
    /// The approval account of this transact (`approval_pda(private_tx_hash)`)
    /// when a withdrawal leg falls under an approval rule.
    pub approval: Option<Address>,
    /// Settlement accounts for the payload's `interface_transfers`, in the same
    /// order.
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    /// Proof of the `auditor_key_encryption` circuit, in the program's wire
    /// encoding. Convert a prover result with `AuditProof::from(..)`.
    pub audit_proof: AuditProof,
    /// The SPP payload. Its `messages` must already carry the auditor message that
    /// the proof commits to, and its `private_tx_hash` must be the one the SPP
    /// proof was generated for.
    pub transact: TransactIxData,
}

impl RingTransactWithAudit {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        let Self {
            payer,
            input_tree,
            output_tree,
            owner_signers,
            approval,
            interface_transfer_accounts,
            audit_proof,
            transact,
        } = self;

        let ring = RingTransact {
            payer,
            input_tree,
            output_tree,
            ring_program_id: PROGRAM_ID,
            owner_signers,
            interface_transfer_accounts,
            data: transact,
        };
        // `.instruction()` (not `.cpi_instruction()`) is the client-facing form:
        // it targets a ring program and leaves `ring_config` unsigned.
        let spp_accounts = ring.instruction().accounts;
        let transact = ring.data;

        let mut accounts = Vec::with_capacity(3 + spp_accounts.len());
        accounts.push(AccountMeta::new(payer, true));
        accounts.push(AccountMeta::new_readonly(config_pda(), false));
        if let Some(approval) = approval {
            accounts.push(AccountMeta::new(approval, false));
        }
        accounts.extend(spp_accounts);

        let body = wincode::serialize(&CustomRingTransactIxData {
            proof: audit_proof,
            transact,
        })?;
        let mut data = Vec::with_capacity(1 + body.len());
        data.push(tag::TRANSACT);
        data.extend_from_slice(&body);

        Ok(Instruction {
            program_id: PROGRAM_ID,
            accounts,
            data,
        })
    }
}
