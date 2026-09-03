//! Entry writes and governed transfers shared by the policy suites, and the
//! tables they pin.

use anyhow::{anyhow, Result};
use custom_ring_sdk::{
    CreateEntry, CustomRing, CustomRingTransfer, CustomRingTransferInput, DepositAsset,
    EntryProofEnvironment, PolicyConfig, ProvenTransfer, ReadEntry, RingDeposit,
    RingDepositReceipt, TransferError, TransferProofEnvironment, UpdateEntry, V0WithLookupTable,
    ENTRY_MUTATION_COMPUTE_UNIT_LIMIT,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{ProverClient, Rpc};
use zolana_keypair::{ShieldedKeypair, ViewingKey};
use zolana_ring_policy::{
    EntryState, ListEntry, ListId, ListSet, Member, Rule, RuleTable, Subject,
};
use zolana_test_utils::test_validator_asserts::{wait_for_indexed_utxo, wait_for_merkle_proof};
use zolana_transaction::{
    instructions::{transact::ConfidentialTransfer, types::SppProofInputUtxo},
    Utxo, SOL_MINT,
};

use crate::shared::{custom_ring_program_id, setup_with_extra_rings, RegisterRing, TestEnv, Tier};

pub const DEPOSIT: u64 = 1_000_000_000;
pub const TRANSFER_AMOUNT: u64 = 250_000_000;

pub const EMPTY: RuleTable = RuleTable::empty();

pub const RELEASED: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
    .rule(Rule::require(Subject::Sender, ListId::Allow))
    .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
    .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
    .build();

pub const BLOCK_ONLY: RuleTable = RuleTable::builder()
    .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
    .build();

pub const TOKEN_BLOCK: RuleTable = RuleTable::builder()
    .rule(Rule::forbid(Subject::Asset, ListId::Block))
    .build();

/// An Approval entry or no Block entry admits an output owner.
pub const APPROVAL_OR_UNBLOCKED: RuleTable = RuleTable::builder()
    .rule(Rule::any_of(
        Subject::OutputOwner,
        ListSet::single(ListId::Approval),
        ListSet::single(ListId::Block),
    ))
    .build();

pub fn owner_member(owner: &ShieldedKeypair) -> Result<Member> {
    Ok(Member::owner_tag(
        &owner.signing_pubkey().confidential_view_tag()?,
    )?)
}

pub fn policy_config<R: Rpc>(ring: CustomRing, rpc: &R) -> Result<PolicyConfig> {
    ring.read_policy_config(rpc)?
        .ok_or_else(|| anyhow!("policy config of {}", ring.program_id()))
}

pub struct CuratedRings {
    pub env: TestEnv,
    pub curator: CustomRing,
    pub subscriber: CustomRing,
}

impl CuratedRings {
    /// The curator pins and registers under the payer, the subscriber stays unconfigured.
    pub fn setup() -> Result<Self> {
        let curator_program = Keypair::new().pubkey();
        let env = setup_with_extra_rings(&[curator_program])?;
        let curator = CustomRing::new(curator_program);
        RegisterRing {
            ring: curator,
            payer: &env.payer,
            auditor_pubkey: ViewingKey::new().pubkey(),
            tier: Tier::policy(&BLOCK_ONLY, env.tree),
        }
        .send(env.client.rpc())?;
        Ok(Self {
            env,
            curator,
            subscriber: CustomRing::new(custom_ring_program_id()?),
        })
    }
}

/// Ring SOL notes of `owner`, each provable through the indexer on return.
pub struct RingNotes<'a> {
    pub ring: CustomRing,
    pub owner: &'a ShieldedKeypair,
    pub amount: u64,
    pub count: usize,
    pub env: &'a TestEnv,
}

impl RingNotes<'_> {
    pub fn deposit(self) -> Result<Vec<Utxo>> {
        let rpc = self.env.client.rpc();
        let indexer = self.env.client.indexer();
        (0..self.count)
            .map(|_| {
                let RingDepositReceipt { utxo, .. } = RingDeposit {
                    ring: self.ring,
                    payer: self.owner,
                    recipient: self.owner,
                    tree: self.env.tree,
                    asset: DepositAsset::Sol,
                    amount: self.amount,
                }
                .send(rpc)?;
                let leaf = SppProofInputUtxo::new(utxo.clone(), self.owner).hash()?;
                wait_for_merkle_proof(indexer, self.env.tree, leaf);
                Ok(utxo)
            })
            .collect()
    }
}

/// One 1-in 2-out ring transfer of `amount` to the recipient.
pub struct PolicyTransfer<'a> {
    pub ring: CustomRing,
    pub sender: &'a ShieldedKeypair,
    pub recipient: &'a ShieldedKeypair,
    pub note: Utxo,
    pub amount: u64,
    pub env: &'a TestEnv,
}

impl PolicyTransfer<'_> {
    pub fn prove(self, prover: &ProverClient) -> Result<ProvenTransfer, TransferError> {
        let mut transfer = ConfidentialTransfer::new(
            self.sender.shielded_address()?,
            vec![SppProofInputUtxo::new(self.note, self.sender)],
            self.sender.pubkey(),
        )
        .with_compact_change()
        .with_ring_program_id(self.ring.program_id());
        transfer.send(&self.recipient.shielded_address()?, SOL_MINT, self.amount)?;
        CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            prepared: transfer.prepare()?,
        })
        .with_tree(self.env.tree)
        .with_assets(&self.env.assets)
        .prove(TransferProofEnvironment {
            indexer: self.env.client.indexer(),
            rpc: self.env.client.rpc(),
            prover,
        })
    }

    /// Refused at witness build, the unreachable prover is never asked.
    pub fn expect_refusal(self) -> Result<()> {
        let unreachable = ProverClient::new("http://127.0.0.1:1".to_string());
        match self.prove(&unreachable) {
            Err(TransferError::PolicyRuleUnsatisfied) => Ok(()),
            Err(other) => Err(anyhow!("expected PolicyRuleUnsatisfied, got {other}")),
            Ok(_) => Err(anyhow!(
                "expected PolicyRuleUnsatisfied, the transfer was proven"
            )),
        }
    }

    /// Returns once photon serves the first output leaf, the next proof sees a synced index.
    pub fn land(self, prover: &ProverClient) -> Result<Signature> {
        let env = self.env;
        let payer = self.sender;
        let proven = self
            .prove(prover)
            .map_err(|error| anyhow!("transfer proof failed {error}"))?;
        let landed = proven
            .data
            .outputs
            .first()
            .ok_or_else(|| anyhow!("transfer output"))?
            .utxo_hash;
        let signature = V0WithLookupTable {
            payer,
            signers: &[],
            instruction: proven.instruction()?,
        }
        .send(env.client.rpc())?;
        wait_for_merkle_proof(env.client.indexer(), env.tree, landed);
        Ok(signature)
    }
}

pub enum EntryTarget {
    Claim { list_id: ListId, member: Member },
    Successor(ListEntry),
}

/// Landed and readable through the indexer before `send` returns.
pub struct EntryWrite<'a> {
    pub ring: CustomRing,
    pub target: EntryTarget,
    pub state: EntryState,
    /// Pays the transaction, the ring authority co-signs the mutation.
    pub fee_payer: &'a dyn Signer,
    pub env: &'a TestEnv,
}

impl EntryWrite<'_> {
    pub fn send(self, prover: &ProverClient) -> Result<ListEntry> {
        let env = self.env;
        let rpc = env.client.rpc();
        let indexer = env.client.indexer();
        let authority = env.payer.pubkey();
        let environment = EntryProofEnvironment {
            indexer,
            rpc,
            prover,
        };
        let proven = match self.target {
            EntryTarget::Claim { list_id, member } => CreateEntry {
                ring: self.ring,
                payer: authority,
                entries_tree: env.tree,
                list_id,
                member,
                state: self.state,
                content_hash: [0u8; 32],
            }
            .prove(environment)?,
            EntryTarget::Successor(spent) => UpdateEntry {
                ring: self.ring,
                payer: authority,
                entries_tree: env.tree,
                spent,
                state: self.state,
                content_hash: [0u8; 32],
            }
            .prove(environment)?,
        };
        let entry = proven.entry();
        let instructions = [
            ComputeBudgetInstruction::set_compute_unit_limit(ENTRY_MUTATION_COMPUTE_UNIT_LIMIT),
            proven.instruction()?,
        ];
        let signers: Vec<&dyn Signer> = if self.fee_payer.pubkey() == authority {
            vec![&env.payer]
        } else {
            vec![self.fee_payer, &env.payer]
        };
        let signature =
            rpc.create_and_send_transaction(&instructions, self.fee_payer.pubkey(), &signers)?;
        wait_for_indexed_utxo(indexer, self.ring.namespace_pda().to_bytes(), signature);
        let live = ReadEntry {
            entries_tree: env.tree,
            namespace: self.ring.namespace_pda(),
            list_id: entry.list_id,
            member: entry.member,
        }
        .read(indexer)?
        .ok_or_else(|| anyhow!("{:?} entry after the write", entry.list_id))?;
        assert_eq!(live.entry, entry, "indexed entry equals the mutation");
        wait_for_merkle_proof(indexer, env.tree, live.utxo_hash);
        Ok(entry)
    }
}
