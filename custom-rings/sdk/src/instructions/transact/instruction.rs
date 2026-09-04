use custom_ring_interface::{tag, CustomRingProof, CustomRingTransactIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::instruction::{
    RingTransact, TransactInterfaceTransferAccounts, TransactIxData,
};

use crate::CustomRing;

#[must_use]
/// Audited ring transact: the ring's auditor key-encryption proof followed by the
/// SPP content it forwards.
///
/// A policy ring prepends `[payer, config, policy_config, entries_tree]` to SPP's
/// own `RING_TRANSACT` list, an audit-only ring prepends just `[payer, config]`.
/// The config holds the auditor key the public-input hash is recomputed against,
/// and a policy ring's `entries_tree` is the only tree the policy roots are read
/// from. Everything after the prefix is forwarded to SPP position for
/// position, so it is taken straight from [`RingTransact::instruction`] rather
/// than re-listed here -- a hand-written copy would be a second definition of
/// SPP's loader order, free to drift from it.
///
/// `ring_config` (this program's `ring_auth` PDA) stays unsigned: no keypair
/// exists for it, and the program is what flips the meta to a signer inside its
/// CPI. Marking it a signer here would make the transaction unsignable.
pub struct CustomRingTransact {
    pub ring: CustomRing,
    pub payer: Address,
    pub input_tree: Address,
    pub output_tree: Address,
    /// The pinned entries tree for a policy ring, `None` for an audit-only ring
    /// whose layout drops the policy_config and entries_tree accounts.
    pub entries_tree: Option<Address>,
    /// The eddsa owners of the spent UTXOs; SPP requires each as a signer.
    pub owner_signers: Vec<Address>,
    /// Settlement accounts for the content's `interface_transfers`, in the same
    /// order.
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    /// Proof of the `audit` circuit, in the program's wire encoding. Convert a
    /// prover result with `CustomRingProof::from(..)`.
    pub proof: CustomRingProof,
    /// The SPP content. Its `messages` must already carry the auditor message that
    /// the proof commits to, and its `private_tx_hash` must be the one the SPP
    /// proof was generated for.
    pub transact: TransactIxData,
    /// History entries a policy statement binds, unread by a ring without rules.
    pub state_root_index: u16,
    pub nullifier_root_index: u16,
}

impl CustomRingTransact {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        let Self {
            ring: deployment,
            payer,
            input_tree,
            output_tree,
            entries_tree,
            owner_signers,
            interface_transfer_accounts,
            proof,
            transact,
            state_root_index,
            nullifier_root_index,
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

        let mut accounts = Vec::with_capacity(4 + spp_accounts.len());
        accounts.push(AccountMeta::new(payer, true));
        accounts.push(AccountMeta::new_readonly(deployment.config_pda(), false));
        if let Some(entries_tree) = entries_tree {
            accounts.push(AccountMeta::new_readonly(
                deployment.policy_config_pda(),
                false,
            ));
            // An existing ring may alias entries_tree with the writable SPP input
            // tree.
            accounts.push(AccountMeta::new_readonly(entries_tree, false));
        }
        accounts.extend(spp_accounts);

        let body = wincode::serialize(&CustomRingTransactIxData {
            proof,
            state_root_index,
            nullifier_root_index,
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
