use custom_ring_interface::{tag, CustomRingProof, CustomRingTransactIxData};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_interface::instruction::{
    RingTransact, TransactInterfaceTransferAccounts, TransactIxData,
};
use zolana_transaction::SOL_MINT;

use crate::{
    instructions::{
        cosigner::{RingPolicy, RingPrefix},
        spend_window::window_metas,
    },
    CustomRing,
};

#[must_use]
/// Audited ring transact: the ring's auditor key-encryption proof followed by the
/// SPP content it forwards.
///
/// A policy ring prepends `[payer, config, cosigner_pda, cosigner, policy_config,
/// entries_tree]` to SPP's own `RING_TRANSACT` list, an audit-only ring prepends
/// just `[payer, config, cosigner_pda, cosigner]`, then one spend window slot
/// per public leg. The `cosigner` slot signs only when the ring has a
/// co-signer, else it repeats `cosigner_pda`.
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
    /// The ring's shared current-record root, present only for windowed transfers.
    pub head_map_root: Option<Address>,
    pub cosigner: Option<Address>,
    /// The eddsa owners of the spent UTXOs; SPP requires each as a signer.
    pub owner_signers: Vec<Address>,
    /// Settlement accounts for the content's `interface_transfers`, in the same
    /// order.
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    /// Proof of the selected ring statement, from `to_instruction_proof`.
    pub proof: CustomRingProof,
    /// The SPP content. Its `messages` must already carry the auditor message that
    /// the proof commits to, and its `private_tx_hash` must be the one the SPP
    /// proof was generated for.
    pub transact: TransactIxData,
    /// History entries a policy statement binds, unread by an audit-only ring.
    pub state_root_index: u16,
    pub nullifier_root_index: u16,
    /// The dual control bit the velocity statement proves, the co-signer then signs.
    pub approval_required: bool,
    pub head_transition: Option<custom_ring_interface::HeadMapTransition>,
}

impl CustomRingTransact {
    pub fn instruction(self) -> Result<Instruction, wincode::Error> {
        let Self {
            ring: deployment,
            payer,
            input_tree,
            output_tree,
            entries_tree,
            head_map_root,
            cosigner,
            owner_signers,
            interface_transfer_accounts,
            proof,
            transact,
            state_root_index,
            nullifier_root_index,
            approval_required,
            head_transition,
        } = self;

        let windows: Vec<AccountMeta> = window_metas(
            deployment,
            interface_transfer_accounts.iter().map(settled_mint),
        )
        .collect();
        let ring = RingTransact {
            payer,
            input_trees: vec![input_tree],
            output_tree,
            ring_program_id: deployment.program_id(),
            owner_signers,
            interface_transfer_accounts,
            data: transact,
        };
        // `.instruction()` (not `.cpi_instruction()`) is the client-facing form:
        // it targets a ring program and leaves `ring_config` unsigned.
        let mut spp_accounts = ring.instruction().accounts;
        // The program raises the namespace PDA as a signer inside its CPI.
        let namespace = deployment.namespace_pda();
        for meta in spp_accounts
            .iter_mut()
            .filter(|meta| meta.pubkey == namespace)
        {
            meta.is_signer = false;
        }
        let transact = ring.data;

        let mut accounts = Vec::with_capacity(6 + spp_accounts.len());
        accounts.push(AccountMeta::new(payer, true));
        // An existing ring may alias entries_tree with the writable SPP input tree.
        accounts.extend(
            RingPrefix {
                ring: deployment,
                cosigner,
                policy: entries_tree.map_or(RingPolicy::Off, RingPolicy::Entries),
            }
            .metas(),
        );
        if let Some(head_map_root) = head_map_root.filter(|_| entries_tree.is_some()) {
            accounts.push(AccountMeta::new(head_map_root, false));
        }
        accounts.extend(windows);
        accounts.extend(spp_accounts);

        let body = wincode::serialize(&CustomRingTransactIxData {
            proof,
            state_root_index,
            nullifier_root_index,
            approval_required: u8::from(approval_required),
            head_transition,
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

fn settled_mint(accounts: &TransactInterfaceTransferAccounts) -> Address {
    match accounts {
        TransactInterfaceTransferAccounts::Sol(_) => SOL_MINT,
        TransactInterfaceTransferAccounts::SplDeposit(spl) => spl.mint,
        TransactInterfaceTransferAccounts::SplWithdrawal(spl) => spl.mint,
    }
}
