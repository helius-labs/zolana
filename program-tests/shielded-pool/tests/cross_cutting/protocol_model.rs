use std::collections::BTreeMap;

use proptest::prelude::*;
use zolana_test_utils::state_model::{
    Action, ExecutionRail, ModelBackend, ModelError, ShieldedPoolBackend,
};

#[derive(Clone, Debug)]
enum DataAction {
    Deposit(u8, u8, u64),
    Transfer(u8, u8, u8, u64),
    Withdraw(u8, u8, u64),
}

fn data_action() -> impl Strategy<Value = DataAction> {
    prop_oneof![
        4 => (0u8..4, 0u8..3, 0u64..=100).prop_map(|(a, asset, amount)| DataAction::Deposit(a, asset, amount)),
        4 => (0u8..4, 0u8..4, 0u8..3, 0u64..=100).prop_map(|(from, to, asset, amount)| DataAction::Transfer(from, to, asset, amount)),
        2 => (0u8..4, 0u8..3, 0u64..=100).prop_map(|(a, asset, amount)| DataAction::Withdraw(a, asset, amount)),
    ]
}

#[derive(Default)]
struct IndependentLedger {
    shielded: BTreeMap<(u8, u8), u64>,
    custody: BTreeMap<u8, u64>,
    public: BTreeMap<(u8, u8), u64>,
}

impl IndependentLedger {
    fn apply(&mut self, action: &DataAction) -> Result<(), ModelError> {
        match *action {
            DataAction::Deposit(actor, asset, amount) => {
                if amount == 0 {
                    return Err(ModelError::ZeroAmount);
                }
                *self.shielded.entry((actor, asset)).or_default() += amount;
                *self.custody.entry(asset).or_default() += amount;
            }
            DataAction::Transfer(from, to, asset, amount) => {
                if amount == 0 {
                    return Err(ModelError::ZeroAmount);
                }
                let available = self
                    .shielded
                    .get(&(from, asset))
                    .copied()
                    .unwrap_or_default();
                if available < amount {
                    return Err(ModelError::InsufficientFunds);
                }
                *self.shielded.entry((from, asset)).or_default() -= amount;
                *self.shielded.entry((to, asset)).or_default() += amount;
            }
            DataAction::Withdraw(actor, asset, amount) => {
                if amount == 0 {
                    return Err(ModelError::ZeroAmount);
                }
                let available = self
                    .shielded
                    .get(&(actor, asset))
                    .copied()
                    .unwrap_or_default();
                if available < amount {
                    return Err(ModelError::InsufficientFunds);
                }
                *self.shielded.entry((actor, asset)).or_default() -= amount;
                *self.custody.entry(asset).or_default() -= amount;
                *self.public.entry((actor, asset)).or_default() += amount;
            }
        }
        Ok(())
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, max_shrink_iters: 16_384, .. ProptestConfig::default() })]

    /// Differential property: UTXO selection/change in the transition oracle must
    /// be observationally equivalent to a separately implemented balance ledger.
    #[test]
    fn data_plane_matches_independent_ledger(actions in prop::collection::vec(data_action(), 1..160)) {
        let mut backend = ModelBackend::new(9);
        let mut ledger = IndependentLedger::default();

        for (nonce, raw) in actions.iter().enumerate() {
            let action = match *raw {
                DataAction::Deposit(actor, asset, amount) => Action::Deposit { actor, asset, amount },
                DataAction::Transfer(from, to, asset, amount) => Action::Transfer {
                    from,
                    to,
                    asset,
                    amount,
                    expiry: u64::MAX,
                    nonce: nonce as u64,
                    rail: ExecutionRail::P256 { owner: from },
                },
                DataAction::Withdraw(actor, asset, amount) => Action::Withdraw {
                    actor,
                    asset,
                    amount,
                    expiry: u64::MAX,
                    nonce: nonce as u64,
                    rail: ExecutionRail::Eddsa { signer: actor },
                },
            };
            let expected = ledger.apply(raw);
            let actual = backend.apply(&action);
            prop_assert_eq!(actual, expected, "action={:?}", raw);

            for actor in 0..4 {
                for asset in 0..3 {
                    prop_assert_eq!(
                        backend.state.balance(actor, asset),
                        ledger.shielded.get(&(actor, asset)).copied().unwrap_or_default(),
                        "actor={} asset={} action={:?}", actor, asset, raw
                    );
                }
            }
            prop_assert_eq!(&backend.state.custody, &ledger.custody);
            prop_assert_eq!(&backend.state.public_balances, &ledger.public);
        }
    }
}

#[derive(Clone, Debug)]
enum MixedAction {
    Deposit(u8, u8, u64),
    Transfer(u8, u8, u8, u64, u8, u16),
    Withdraw(u8, u8, u64, u8, u16),
    Pause(u8, bool),
    RotateAuthority(u8, u8),
    RotateRegistry(u8),
    SetZone(u8, u8, bool),
    SetMerge(u8, u8, bool),
    Tick(u16),
}

fn mixed_action() -> impl Strategy<Value = MixedAction> {
    prop_oneof![
        5 => (0u8..5, 0u8..3, 0u64..=500).prop_map(|(a, asset, amount)| MixedAction::Deposit(a, asset, amount)),
        4 => (0u8..5, 0u8..5, 0u8..3, 0u64..=500, 0u8..5, any::<u16>()).prop_map(|(from, to, asset, amount, signer, expiry)| MixedAction::Transfer(from, to, asset, amount, signer, expiry)),
        2 => (0u8..5, 0u8..3, 0u64..=500, 0u8..5, any::<u16>()).prop_map(|(a, asset, amount, signer, expiry)| MixedAction::Withdraw(a, asset, amount, signer, expiry)),
        1 => (0u8..5, any::<bool>()).prop_map(|(authority, paused)| MixedAction::Pause(authority, paused)),
        1 => (0u8..5, 0u8..5).prop_map(|(authority, next)| MixedAction::RotateAuthority(authority, next)),
        1 => (0u8..5).prop_map(MixedAction::RotateRegistry),
        1 => (0u8..5, 0u8..5, any::<bool>()).prop_map(|(authority, zone, enabled)| MixedAction::SetZone(authority, zone, enabled)),
        1 => (0u8..5, 0u8..5, any::<bool>()).prop_map(|(authority, actor, enabled)| MixedAction::SetMerge(authority, actor, enabled)),
        1 => any::<u16>().prop_map(MixedAction::Tick),
    ]
}

/// Independently implemented control-plane oracle for the mixed sequences.
/// The model's `apply` restores state on error by construction, so comparing
/// against a pre-snapshot cannot fail; this shadow re-derives authorization
/// outcomes and the control fields from scratch so the model's policy logic is
/// checked against a second implementation.
struct ControlShadow {
    authority: u8,
    paused: bool,
    registry_version: u64,
    clock: u64,
    zones: std::collections::BTreeSet<u8>,
    merge: std::collections::BTreeSet<u8>,
}

impl ControlShadow {
    fn new(authority: u8) -> Self {
        Self {
            authority,
            paused: false,
            registry_version: 0,
            clock: 0,
            zones: std::collections::BTreeSet::new(),
            merge: std::collections::BTreeSet::new(),
        }
    }

    /// Apply a control-plane action; `Some(outcome)` predicts whether the
    /// model must accept it. Data-plane actions return `None` (the shadow does
    /// not model balances; the 512-case differential above covers those).
    fn apply(&mut self, action: &MixedAction) -> Option<bool> {
        match *action {
            MixedAction::Pause(authority, paused) => {
                let ok = authority == self.authority;
                if ok {
                    self.paused = paused;
                }
                Some(ok)
            }
            MixedAction::RotateAuthority(authority, next) => {
                let ok = authority == self.authority;
                if ok {
                    self.authority = next;
                }
                Some(ok)
            }
            MixedAction::RotateRegistry(authority) => {
                let ok = authority == self.authority;
                if ok {
                    self.registry_version += 1;
                }
                Some(ok)
            }
            MixedAction::SetZone(authority, zone, enabled) => {
                let ok = authority == self.authority;
                if ok {
                    if enabled {
                        self.zones.insert(zone);
                    } else {
                        self.zones.remove(&zone);
                    }
                }
                Some(ok)
            }
            MixedAction::SetMerge(authority, actor, enabled) => {
                let ok = authority == self.authority;
                if ok {
                    if enabled {
                        self.merge.insert(actor);
                    } else {
                        self.merge.remove(&actor);
                    }
                }
                Some(ok)
            }
            MixedAction::Tick(next) => {
                let ok = u64::from(next) >= self.clock;
                if ok {
                    self.clock = u64::from(next);
                }
                Some(ok)
            }
            MixedAction::Deposit(..) | MixedAction::Transfer(..) | MixedAction::Withdraw(..) => {
                None
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 16_384, .. ProptestConfig::default() })]

    /// Long mixed data/control-plane sequences check all conservation and
    /// nullifier invariants after every attempted transition, and compare the
    /// control plane (authorization outcomes and resulting policy state)
    /// against the independent [`ControlShadow`] oracle.
    #[test]
    fn mixed_protocol_sequences_are_atomic(actions in prop::collection::vec(mixed_action(), 24..180)) {
        let mut backend = ModelBackend::new(0);
        let mut shadow = ControlShadow::new(0);
        for (nonce, raw) in actions.iter().enumerate() {
            let action = match *raw {
                MixedAction::Deposit(actor, asset, amount) => Action::Deposit { actor, asset, amount },
                MixedAction::Transfer(from, to, asset, amount, signer, expiry) => Action::Transfer {
                    from, to, asset, amount, expiry: expiry as u64, nonce: nonce as u64,
                    rail: ExecutionRail::P256 { owner: signer },
                },
                MixedAction::Withdraw(actor, asset, amount, signer, expiry) => Action::Withdraw {
                    actor, asset, amount, expiry: expiry as u64, nonce: nonce as u64,
                    rail: ExecutionRail::Eddsa { signer },
                },
                MixedAction::Pause(authority, paused) => Action::SetPaused { authority, paused },
                MixedAction::RotateAuthority(authority, next) => Action::RotateAuthority { authority, next },
                MixedAction::RotateRegistry(authority) => Action::RotateRegistry { authority },
                MixedAction::SetZone(authority, zone, enabled) => Action::SetZone { authority, zone, enabled },
                MixedAction::SetMerge(authority, actor, enabled) => Action::SetMergePermission { authority, actor, enabled },
                MixedAction::Tick(next) => Action::AdvanceClock(next as u64),
            };
            let result = backend.apply(&action);
            if let Some(expected_ok) = shadow.apply(raw) {
                prop_assert_eq!(result.is_ok(), expected_ok, "authorization disagrees: {:?}", raw);
            }
            prop_assert_eq!(backend.state.authority, shadow.authority);
            prop_assert_eq!(backend.state.paused, shadow.paused);
            prop_assert_eq!(backend.state.registry_version, shadow.registry_version);
            prop_assert_eq!(backend.state.clock, shadow.clock);
            prop_assert_eq!(&backend.state.enabled_zones, &shadow.zones);
            prop_assert_eq!(&backend.state.merge_enabled, &shadow.merge);
            backend.state.assert_invariants();
        }
        prop_assert_eq!(backend.journal.len(), actions.len());
    }
}
