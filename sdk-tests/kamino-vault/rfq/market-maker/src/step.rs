use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use solana_address::Address;
use solana_instruction::Instruction;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use tokio::sync::oneshot;
use zolana_client::DEFAULT_TRANSACT_CU_LIMIT;
use zolana_program::instruction::TransactInterfaceTransferAccounts;
use zolana_transaction::{instructions::transact::SppProofInputs, WalletUtxo};

use super::{error::MakerError, send::Sent};
use kamino_vault_rfq_sdk::swap::{Spend, SWAP_COMPUTE_BUDGET};

pub type StepId = u64;
pub type OperationId = u64;

const WIDE_TRANSACT_CU_LIMIT: u32 = 1_400_000;
const WIDE_TRANSACT_INPUTS: usize = 6;
const CLOSE_CACHE_CU_LIMIT: u32 = 50_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepKind {
    Fill,
    Consolidate,
    CloseCache(Address),
}

#[derive(Clone)]
pub struct ProofWork {
    pub inputs: SppProofInputs,
    pub interface_accounts: Vec<TransactInterfaceTransferAccounts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepState {
    Proving,
    Proven,
    AwaitingSignature,
    Sending,
    Sent,
    Confirmed,
}

impl StepState {
    pub fn is_unsent(self) -> bool {
        matches!(self, Self::Proving | Self::Proven | Self::AwaitingSignature)
    }

    pub fn is_on_chain_pending(self) -> bool {
        matches!(self, Self::Sending | Self::Sent)
    }
}

pub struct FillLeg {
    pub user_leg: Instruction,
    pub ttl: Duration,
    pub spends: Vec<Spend>,
    pub change: Vec<WalletUtxo>,
    pub message: Option<VersionedMessage>,
    pub last_valid_block_height: u64,
    pub expires_at: Option<Instant>,
    pub transaction: Option<VersionedTransaction>,
    pub settle: Option<oneshot::Sender<Result<Signature, MakerError>>>,
}

pub struct Step {
    pub id: StepId,
    pub kind: StepKind,
    pub asset: Option<Address>,
    pub operation: Option<OperationId>,
    pub inputs: Vec<[u8; 32]>,
    pub own_outputs: Vec<[u8; 32]>,
    pub read_cache: Option<Address>,
    pub write_cache: Option<Address>,
    pub proof: Option<ProofWork>,
    pub instruction: Option<Instruction>,
    pub fill: Option<FillLeg>,
    pub sends: Vec<Sent>,
    pub resend_failed: bool,
    pub state: StepState,
    pub prove_attempts: u32,
}

impl Step {
    pub fn new(id: StepId, kind: StepKind, proof: Option<ProofWork>) -> Self {
        Self {
            id,
            kind,
            asset: None,
            operation: None,
            inputs: Vec::new(),
            own_outputs: Vec::new(),
            read_cache: None,
            write_cache: None,
            proof,
            instruction: None,
            fill: None,
            sends: Vec::new(),
            resend_failed: false,
            state: StepState::Proving,
            prove_attempts: 0,
        }
    }

    pub fn is_upkeep(&self) -> bool {
        self.operation.is_none() && self.kind == StepKind::Consolidate
    }

    pub fn uses_cache(&self, cache: &Address) -> bool {
        self.read_cache.as_ref() == Some(cache) || self.write_cache.as_ref() == Some(cache)
    }

    pub fn compute_units(&self) -> u32 {
        match self.kind {
            StepKind::CloseCache(_) => CLOSE_CACHE_CU_LIMIT,
            StepKind::Fill => SWAP_COMPUTE_BUDGET.cu_limit,
            StepKind::Consolidate if self.inputs.len() >= WIDE_TRANSACT_INPUTS => {
                WIDE_TRANSACT_CU_LIMIT
            }
            StepKind::Consolidate => DEFAULT_TRANSACT_CU_LIMIT,
        }
    }
}

#[derive(Default)]
pub struct StepGraph {
    steps: HashMap<StepId, Step>,
    next_id: StepId,
}

impl StepGraph {
    pub fn next_id(&mut self) -> StepId {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    pub fn insert(&mut self, step: Step) {
        self.steps.insert(step.id, step);
    }

    pub fn get(&self, id: StepId) -> Option<&Step> {
        self.steps.get(&id)
    }

    pub fn get_mut(&mut self, id: StepId) -> Option<&mut Step> {
        self.steps.get_mut(&id)
    }

    pub fn remove(&mut self, id: StepId) -> Option<Step> {
        self.steps.remove(&id)
    }

    pub fn ready_to_send(&self) -> Vec<StepId> {
        self.steps
            .values()
            .filter(|step| step.state == StepState::Proven && step.kind != StepKind::Fill)
            .map(|step| step.id)
            .collect()
    }

    pub fn in_flight(&self) -> impl Iterator<Item = &Step> {
        self.steps
            .values()
            .filter(|step| step.state != StepState::Confirmed)
    }

    pub fn sent(&self) -> impl Iterator<Item = &Step> {
        self.steps
            .values()
            .filter(|step| step.state == StepState::Sent)
    }

    pub fn is_idle(&self) -> bool {
        self.in_flight().next().is_none()
    }

    pub fn has_pending_sends(&self) -> bool {
        self.in_flight()
            .any(|step| step.state.is_on_chain_pending())
    }

    pub fn prune_confirmed(&mut self) {
        self.steps
            .retain(|_, step| step.state != StepState::Confirmed);
    }
}
