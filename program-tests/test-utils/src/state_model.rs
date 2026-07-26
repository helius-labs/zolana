//! Backend-neutral shielded-pool state-transition oracle.
//!
//! The model deliberately contains no Solana, prover, wallet, or indexer code.
//! A workflow backend can run an operation and compare its decoded post-state
//! with this oracle; pure property tests can also exercise long mixed data- and
//! control-plane sequences without starting external services.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type ActorId = u8;
pub type AssetId = u8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelUtxo {
    pub id: u64,
    pub owner: ActorId,
    pub asset: AssetId,
    pub amount: u64,
    pub spent: bool,
    /// Registry version at creation time. It is retained as history, but UTXO
    /// spendability intentionally does not depend on the current version.
    pub registry_version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionRail {
    P256 {
        owner: ActorId,
    },
    Eddsa {
        signer: ActorId,
    },
    Zone {
        owner: ActorId,
        zone: ActorId,
    },
    /// Threshold/timelock authorization in the style of the external Squads
    /// smart-account program. The SPP program has no such rail: this variant
    /// exists only in the reference model (exercised by
    /// `authorization_contract`) and asserts nothing about on-chain behavior.
    SmartAccount {
        owner: ActorId,
        members: BTreeSet<ActorId>,
        signatures: BTreeSet<ActorId>,
        threshold: usize,
        execute_after: u64,
    },
}

impl ExecutionRail {
    fn authorize(
        &self,
        expected_owner: ActorId,
        now: u64,
        enabled_zones: &BTreeSet<ActorId>,
    ) -> Result<(), ModelError> {
        match self {
            Self::P256 { owner } if *owner == expected_owner => Ok(()),
            Self::Eddsa { signer } if *signer == expected_owner => Ok(()),
            Self::Zone { owner, zone }
                if *owner == expected_owner && enabled_zones.contains(zone) =>
            {
                Ok(())
            }
            Self::SmartAccount {
                owner,
                members,
                signatures,
                threshold,
                execute_after,
            } if *owner == expected_owner => {
                if now < *execute_after {
                    return Err(ModelError::TimelockActive);
                }
                if *threshold == 0 || *threshold > members.len() {
                    return Err(ModelError::InvalidThreshold);
                }
                let approvals = signatures.intersection(members).count();
                if approvals < *threshold {
                    return Err(ModelError::InsufficientApprovals);
                }
                Ok(())
            }
            _ => Err(ModelError::Unauthorized),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchPlan {
    pub generation: u64,
    pub nullifiers: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelError {
    Paused,
    ZeroAmount,
    InsufficientFunds,
    Unauthorized,
    Expired,
    Replay,
    TimelockActive,
    InvalidThreshold,
    InsufficientApprovals,
    MergeDisabled,
    InvalidBatch,
    BatchNotReady,
    ClockWentBackwards,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    AdvanceClock(u64),
    SetPaused {
        authority: ActorId,
        paused: bool,
    },
    RotateAuthority {
        authority: ActorId,
        next: ActorId,
    },
    RotateRegistry {
        authority: ActorId,
    },
    SetZone {
        authority: ActorId,
        zone: ActorId,
        enabled: bool,
    },
    SetMergePermission {
        authority: ActorId,
        actor: ActorId,
        enabled: bool,
    },
    Deposit {
        actor: ActorId,
        asset: AssetId,
        amount: u64,
    },
    Transfer {
        from: ActorId,
        to: ActorId,
        asset: AssetId,
        amount: u64,
        expiry: u64,
        nonce: u64,
        rail: ExecutionRail,
    },
    Withdraw {
        actor: ActorId,
        asset: AssetId,
        amount: u64,
        expiry: u64,
        nonce: u64,
        rail: ExecutionRail,
    },
    Consolidate {
        actor: ActorId,
        asset: AssetId,
        max_inputs: usize,
        expiry: u64,
        nonce: u64,
        rail: ExecutionRail,
    },
    ExecuteBatch {
        authority: ActorId,
        plan: BatchPlan,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolState {
    pub clock: u64,
    pub authority: ActorId,
    pub paused: bool,
    pub registry_version: u64,
    pub enabled_zones: BTreeSet<ActorId>,
    pub merge_enabled: BTreeSet<ActorId>,
    pub utxos: Vec<ModelUtxo>,
    pub custody: BTreeMap<AssetId, u64>,
    pub public_balances: BTreeMap<(ActorId, AssetId), u64>,
    pub used_nonces: BTreeSet<u64>,
    pub queued_nullifiers: VecDeque<u64>,
    pub processed_nullifiers: Vec<u64>,
    pub batch_generation: u64,
    next_utxo_id: u64,
}

impl ProtocolState {
    pub fn new(authority: ActorId) -> Self {
        Self {
            clock: 0,
            authority,
            paused: false,
            registry_version: 0,
            enabled_zones: BTreeSet::new(),
            merge_enabled: BTreeSet::new(),
            utxos: Vec::new(),
            custody: BTreeMap::new(),
            public_balances: BTreeMap::new(),
            used_nonces: BTreeSet::new(),
            queued_nullifiers: VecDeque::new(),
            processed_nullifiers: Vec::new(),
            batch_generation: 0,
            next_utxo_id: 0,
        }
    }

    /// Apply one transition atomically. Any error restores the exact pre-state.
    pub fn apply(&mut self, action: &Action) -> Result<(), ModelError> {
        let before = self.clone();
        if let Err(error) = self.apply_inner(action) {
            *self = before;
            return Err(error);
        }
        self.assert_invariants();
        Ok(())
    }

    fn apply_inner(&mut self, action: &Action) -> Result<(), ModelError> {
        match action {
            Action::AdvanceClock(next) => {
                if *next < self.clock {
                    return Err(ModelError::ClockWentBackwards);
                }
                self.clock = *next;
            }
            Action::SetPaused { authority, paused } => {
                self.require_authority(*authority)?;
                self.paused = *paused;
            }
            Action::RotateAuthority { authority, next } => {
                self.require_authority(*authority)?;
                self.authority = *next;
            }
            Action::RotateRegistry { authority } => {
                self.require_authority(*authority)?;
                self.registry_version = self
                    .registry_version
                    .checked_add(1)
                    .ok_or(ModelError::ArithmeticOverflow)?;
            }
            Action::SetZone {
                authority,
                zone,
                enabled,
            } => {
                self.require_authority(*authority)?;
                if *enabled {
                    self.enabled_zones.insert(*zone);
                } else {
                    self.enabled_zones.remove(zone);
                }
            }
            Action::SetMergePermission {
                authority,
                actor,
                enabled,
            } => {
                self.require_authority(*authority)?;
                if *enabled {
                    self.merge_enabled.insert(*actor);
                } else {
                    self.merge_enabled.remove(actor);
                }
            }
            Action::Deposit {
                actor,
                asset,
                amount,
            } => self.deposit(*actor, *asset, *amount)?,
            Action::Transfer {
                from,
                to,
                asset,
                amount,
                expiry,
                nonce,
                rail,
            } => {
                self.authorize_spend(*from, *expiry, *nonce, rail)?;
                self.spend_to(*from, *to, *asset, *amount)?;
                self.used_nonces.insert(*nonce);
            }
            Action::Withdraw {
                actor,
                asset,
                amount,
                expiry,
                nonce,
                rail,
            } => {
                self.authorize_spend(*actor, *expiry, *nonce, rail)?;
                self.spend_utxos(*actor, *asset, *amount, None)?;
                let custody = self.custody.entry(*asset).or_default();
                *custody = custody
                    .checked_sub(*amount)
                    .ok_or(ModelError::InsufficientFunds)?;
                let public = self.public_balances.entry((*actor, *asset)).or_default();
                *public = public
                    .checked_add(*amount)
                    .ok_or(ModelError::ArithmeticOverflow)?;
                self.used_nonces.insert(*nonce);
            }
            Action::Consolidate {
                actor,
                asset,
                max_inputs,
                expiry,
                nonce,
                rail,
            } => {
                if !self.merge_enabled.contains(actor) {
                    return Err(ModelError::MergeDisabled);
                }
                self.authorize_spend(*actor, *expiry, *nonce, rail)?;
                let selected: Vec<usize> = self
                    .utxos
                    .iter()
                    .enumerate()
                    .filter(|(_, utxo)| !utxo.spent && utxo.owner == *actor && utxo.asset == *asset)
                    .take(*max_inputs)
                    .map(|(index, _)| index)
                    .collect();
                if selected.is_empty() {
                    return Err(ModelError::InsufficientFunds);
                }
                let amount = selected.iter().try_fold(0u64, |sum, index| {
                    let utxo = self
                        .utxos
                        .get(*index)
                        .expect("selected indices come from enumerate");
                    sum.checked_add(utxo.amount)
                        .ok_or(ModelError::ArithmeticOverflow)
                })?;
                self.consume(&selected);
                self.create_utxo(*actor, *asset, amount)?;
                self.used_nonces.insert(*nonce);
            }
            Action::ExecuteBatch { authority, plan } => {
                self.require_authority(*authority)?;
                self.execute_batch(plan)?;
            }
        }
        Ok(())
    }

    pub fn balance(&self, actor: ActorId, asset: AssetId) -> u64 {
        self.utxos
            .iter()
            .filter(|utxo| !utxo.spent && utxo.owner == actor && utxo.asset == asset)
            .map(|utxo| utxo.amount)
            .sum()
    }

    pub fn spendable_utxos(&self, actor: ActorId, asset: AssetId) -> usize {
        self.utxos
            .iter()
            .filter(|utxo| !utxo.spent && utxo.owner == actor && utxo.asset == asset)
            .count()
    }

    pub fn plan_batch(&self, batch_size: usize) -> Result<BatchPlan, ModelError> {
        if batch_size == 0 || self.queued_nullifiers.len() < batch_size {
            return Err(ModelError::BatchNotReady);
        }
        Ok(BatchPlan {
            generation: self.batch_generation,
            nullifiers: self
                .queued_nullifiers
                .iter()
                .take(batch_size)
                .copied()
                .collect(),
        })
    }

    fn execute_batch(&mut self, plan: &BatchPlan) -> Result<(), ModelError> {
        if plan.generation != self.batch_generation || plan.nullifiers.is_empty() {
            return Err(ModelError::InvalidBatch);
        }
        let expected: Vec<u64> = self
            .queued_nullifiers
            .iter()
            .take(plan.nullifiers.len())
            .copied()
            .collect();
        if expected != plan.nullifiers {
            return Err(ModelError::InvalidBatch);
        }
        for nullifier in &plan.nullifiers {
            let queued = self.queued_nullifiers.pop_front();
            debug_assert_eq!(queued, Some(*nullifier));
            self.processed_nullifiers.push(*nullifier);
        }
        self.batch_generation = self
            .batch_generation
            .checked_add(1)
            .ok_or(ModelError::ArithmeticOverflow)?;
        Ok(())
    }

    fn require_authority(&self, authority: ActorId) -> Result<(), ModelError> {
        (authority == self.authority)
            .then_some(())
            .ok_or(ModelError::Unauthorized)
    }

    fn authorize_spend(
        &self,
        owner: ActorId,
        expiry: u64,
        nonce: u64,
        rail: &ExecutionRail,
    ) -> Result<(), ModelError> {
        if self.paused {
            return Err(ModelError::Paused);
        }
        if self.clock > expiry {
            return Err(ModelError::Expired);
        }
        if self.used_nonces.contains(&nonce) {
            return Err(ModelError::Replay);
        }
        rail.authorize(owner, self.clock, &self.enabled_zones)
    }

    fn deposit(&mut self, actor: ActorId, asset: AssetId, amount: u64) -> Result<(), ModelError> {
        if self.paused {
            return Err(ModelError::Paused);
        }
        if amount == 0 {
            return Err(ModelError::ZeroAmount);
        }
        let custody = self.custody.entry(asset).or_default();
        *custody = custody
            .checked_add(amount)
            .ok_or(ModelError::ArithmeticOverflow)?;
        self.create_utxo(actor, asset, amount)
    }

    fn spend_to(
        &mut self,
        from: ActorId,
        to: ActorId,
        asset: AssetId,
        amount: u64,
    ) -> Result<(), ModelError> {
        self.spend_utxos(from, asset, amount, Some(to))
    }

    fn spend_utxos(
        &mut self,
        owner: ActorId,
        asset: AssetId,
        amount: u64,
        recipient: Option<ActorId>,
    ) -> Result<(), ModelError> {
        if amount == 0 {
            return Err(ModelError::ZeroAmount);
        }
        let mut selected = Vec::new();
        let mut total = 0u64;
        for (index, utxo) in self.utxos.iter().enumerate() {
            if utxo.spent || utxo.owner != owner || utxo.asset != asset {
                continue;
            }
            selected.push(index);
            total = total
                .checked_add(utxo.amount)
                .ok_or(ModelError::ArithmeticOverflow)?;
            if total >= amount {
                break;
            }
        }
        if total < amount {
            return Err(ModelError::InsufficientFunds);
        }
        self.consume(&selected);
        if let Some(recipient) = recipient {
            self.create_utxo(recipient, asset, amount)?;
        }
        let change = total - amount;
        if change > 0 {
            self.create_utxo(owner, asset, change)?;
        }
        Ok(())
    }

    fn consume(&mut self, selected: &[usize]) {
        for index in selected {
            let utxo = self
                .utxos
                .get_mut(*index)
                .expect("selected indices come from enumerate");
            utxo.spent = true;
            self.queued_nullifiers.push_back(utxo.id);
        }
    }

    fn create_utxo(
        &mut self,
        owner: ActorId,
        asset: AssetId,
        amount: u64,
    ) -> Result<(), ModelError> {
        let id = self.next_utxo_id;
        self.next_utxo_id = id.checked_add(1).ok_or(ModelError::ArithmeticOverflow)?;
        self.utxos.push(ModelUtxo {
            id,
            owner,
            asset,
            amount,
            spent: false,
            registry_version: self.registry_version,
        });
        Ok(())
    }

    #[track_caller]
    pub fn assert_invariants(&self) {
        let mut live_by_asset = BTreeMap::<AssetId, u64>::new();
        let mut ids = BTreeSet::new();
        for utxo in &self.utxos {
            assert!(ids.insert(utxo.id), "duplicate UTXO id {}", utxo.id);
            if !utxo.spent {
                let entry = live_by_asset.entry(utxo.asset).or_default();
                *entry = entry
                    .checked_add(utxo.amount)
                    .expect("invariant checker overflow: live shielded value exceeds u64");
            }
        }
        // Bidirectional check: every custody entry equals the live UTXO total for
        // that asset, and every asset with live UTXOs has a matching custody entry.
        for (asset, custody) in &self.custody {
            assert_eq!(
                live_by_asset.get(asset).copied().unwrap_or_default(),
                *custody,
                "live shielded value must equal custody for asset {asset}"
            );
        }
        for (asset, live) in &live_by_asset {
            assert_eq!(
                self.custody.get(asset).copied().unwrap_or_default(),
                *live,
                "custody entry must match live shielded value for asset {asset}"
            );
        }
        let queued: BTreeSet<u64> = self.queued_nullifiers.iter().copied().collect();
        assert_eq!(
            queued.len(),
            self.queued_nullifiers.len(),
            "queued nullifiers must be unique"
        );
        let processed: BTreeSet<u64> = self.processed_nullifiers.iter().copied().collect();
        assert_eq!(
            processed.len(),
            self.processed_nullifiers.len(),
            "processed nullifiers must be unique"
        );
        assert!(
            queued.is_disjoint(&processed),
            "a nullifier cannot be queued and processed"
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionRecord {
    pub action: Action,
    pub before: ProtocolState,
    pub result: Result<(), ModelError>,
    pub after: ProtocolState,
}

/// Shared workflow vocabulary with an automatically journaled reference
/// backend. RPC/LiteSVM harness adapters can implement this trait and compare
/// their decoded snapshot after every action with [`ModelBackend::state`].
pub trait ShieldedPoolBackend {
    type Snapshot: Clone + std::fmt::Debug + PartialEq + Eq;
    type Error;

    fn snapshot(&self) -> Self::Snapshot;
    fn apply(&mut self, action: &Action) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug)]
pub struct ModelBackend {
    pub state: ProtocolState,
    pub journal: Vec<TransitionRecord>,
}

impl ModelBackend {
    pub fn new(authority: ActorId) -> Self {
        Self {
            state: ProtocolState::new(authority),
            journal: Vec::new(),
        }
    }

    /// Re-run a captured action script from a clean state. This is the stable
    /// committed-regression format used by property tests after shrinking.
    pub fn replay(authority: ActorId, actions: &[Action]) -> Self {
        let mut backend = Self::new(authority);
        for action in actions {
            let _ = backend.apply(action);
        }
        backend
    }
}

impl ShieldedPoolBackend for ModelBackend {
    type Snapshot = ProtocolState;
    type Error = ModelError;

    fn snapshot(&self) -> Self::Snapshot {
        self.state.clone()
    }

    fn apply(&mut self, action: &Action) -> Result<(), Self::Error> {
        let before = self.snapshot();
        let result = self.state.apply(action);
        self.journal.push(TransitionRecord {
            action: action.clone(),
            before,
            result: result.clone(),
            after: self.snapshot(),
        });
        result
    }
}
