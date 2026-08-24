use custom_ring_interface::{tag, AuditProof, CustomRingTransactIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::instruction::{
    RingTransact, TransactInterfaceTransferAccounts, TransactIxData,
};

use crate::CustomRing;

#[must_use]
/// Audited ring transact: the ring's auditor key-encryption proof followed by the
/// SPP payload it forwards.
///
/// The account list is `[payer, config]` prepended to SPP's own `RING_TRANSACT`
/// list. Those two extra accounts are all this program reads for itself: the payer
/// it requires as a signer, and the config account holding the auditor key the
/// public-input hash is recomputed against. Everything after them is forwarded to
/// SPP position for position, so it is taken straight from
/// [`RingTransact::instruction`] rather than re-listed here -- a hand-written copy
/// would be a second definition of SPP's loader order, free to drift from it.
///
/// `ring_config` (this program's `ring_auth` PDA) stays unsigned: no keypair
/// exists for it, and the program is what flips the meta to a signer inside its
/// CPI. Marking it a signer here would make the transaction unsignable.
pub struct RingTransactWithAudit {
    pub ring: CustomRing,
    pub payer: Address,
    pub input_tree: Address,
    pub output_tree: Address,
    /// The eddsa owners of the spent UTXOs; SPP requires each as a signer.
    pub owner_signers: Vec<Address>,
    /// Settlement accounts for the payload's `interface_transfers`, in the same
    /// order.
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    /// Proof of the `audit` circuit, in the program's wire encoding. Convert a
    /// prover result with `AuditProof::from(..)`.
    pub audit_proof: AuditProof,
    /// The SPP payload. Its `messages` must already carry the auditor message that
    /// the proof commits to, and its `private_tx_hash` must be the one the SPP
    /// proof was generated for.
    pub transact: TransactIxData,
}

impl RingTransactWithAudit {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        let Self {
            ring: deployment,
            payer,
            input_tree,
            output_tree,
            owner_signers,
            interface_transfer_accounts,
            audit_proof,
            transact,
        } = self;

        let ring = RingTransact {
            payer,
            input_tree,
            output_tree,
            ring_program_id: deployment.program_id(),
            owner_signers,
            interface_transfer_accounts,
            data: transact,
        };
        // `.instruction()` (not `.cpi_instruction()`) is the client-facing form:
        // it targets a ring program and leaves `ring_config` unsigned.
        let spp_accounts = ring.instruction().accounts;
        let transact = ring.data;

        let mut accounts = Vec::with_capacity(2 + spp_accounts.len());
        accounts.push(AccountMeta::new(payer, true));
        accounts.push(AccountMeta::new_readonly(deployment.config_pda(), false));
        accounts.extend(spp_accounts);

        let body = wincode::serialize(&CustomRingTransactIxData {
            proof: audit_proof,
            transact,
        })?;
        let mut data = Vec::with_capacity(1 + body.len());
        data.push(tag::TRANSACT);
        data.extend_from_slice(&body);

        Ok(Instruction {
            program_id: deployment.program_id(),
            accounts,
            data,
        })
    }
}
