//! `key`, the member's nullifier key sealed to the ring auditor in the key registry.

use custom_ring_sdk::{
    AccountReadError, CustomRing, IndexedMapRoot, KeyRegistrationError, ReadSealedKey, RegisterKey,
    TransferProofEnvironment, REGISTER_KEY_COMPUTE_UNIT_LIMIT,
};
use solana_signer::Signer;
use thiserror::Error;
use zolana_client::{ClientError, Rpc, SolanaRpc};
use zolana_keypair::{KeypairError, ShieldedKeypair};
use zolana_ring_policy::{Member, MemberError};

use crate::{
    error::boxed_from,
    file::FileError,
    line,
    step::{no_hint, IdempotentStep, Observed, StepError},
    transact::{sender_keypair_file, wait_for, Probe, WaitError, SENDER_FEE_BUDGET},
    ui::{Ask, AskError},
    Context, ContextError, KeyCommand,
};

#[derive(Debug, Error)]
pub enum KeyError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Registration(Box<KeyRegistrationError>),
    #[error(transparent)]
    Step(#[from] StepError),
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    Ask(#[from] AskError),
    #[error(transparent)]
    Client(Box<ClientError>),
    #[error("timed out waiting for {label}")]
    Timeout {
        label: String,
        #[source]
        last: Option<Box<KeyError>>,
    },
    #[error("the ring has no key registry, its authority must run `zolana-ring init` first")]
    NoKeyRegistry,
}

boxed_from!(KeyError {
    Registration(KeyRegistrationError),
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    AlreadyRegistered,
    Enroll,
    Declined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyOutcome {
    Registered,
    Present,
}

/// Registration is once per member, an existing entry keeps its seal.
pub(crate) struct KeyEnrolment<'a> {
    pub ring: CustomRing,
    pub member: &'a ShieldedKeypair,
}

pub fn run(ctx: &mut Context, command: KeyCommand) -> Result<(), KeyError> {
    let sender = sender_keypair_file(ctx)?;
    match command {
        KeyCommand::Register => {
            let member = ShieldedKeypair::from_keypair(&sender)?;
            let enrolment = KeyEnrolment {
                ring: ctx.ring,
                member: &member,
            };
            let indexer = ctx.indexer();
            line("member", sender.pubkey());
            let registered = enrolment.registered(&indexer, &ctx.rpc)?;
            match enrolment.plan(registered, ctx.ask.as_mut())? {
                Plan::AlreadyRegistered => line("key", "already registered"),
                Plan::Declined => line("key", "not registered"),
                Plan::Enroll => {
                    ctx.fund_authority(&sender, SENDER_FEE_BUDGET)?;
                    enrolment.register(TransferProofEnvironment {
                        indexer: &indexer,
                        rpc: &ctx.rpc,
                        prover: &ctx.prover(),
                    })?;
                    line("key", "registered");
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn registry_root(ring: CustomRing, rpc: &impl Rpc) -> Result<IndexedMapRoot, KeyError> {
    ring.read_key_registry_root(rpc)?
        .ok_or(KeyError::NoKeyRegistry)
}

impl KeyOutcome {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Present => "already registered",
        }
    }
}

impl KeyEnrolment<'_> {
    pub(crate) fn ensure<I: Rpc>(
        &self,
        env: TransferProofEnvironment<'_, I, SolanaRpc>,
    ) -> Result<KeyOutcome, KeyError> {
        if self.registered(env.indexer, env.rpc)? {
            return Ok(KeyOutcome::Present);
        }
        self.register(env)?;
        Ok(KeyOutcome::Registered)
    }

    fn plan(&self, registered: bool, ask: &mut dyn Ask) -> Result<Plan, KeyError> {
        if registered {
            return Ok(Plan::AlreadyRegistered);
        }
        if ask.confirm(
            "seal the member key to the ring auditor and register it?",
            true,
        )? {
            Ok(Plan::Enroll)
        } else {
            Ok(Plan::Declined)
        }
    }

    /// Only the sender's key included under the current registry root counts as
    /// enrolled.
    fn registered(&self, indexer: &impl Rpc, rpc: &impl Rpc) -> Result<bool, KeyError> {
        let member = self.member_tag()?;
        let nullifier_pubkey = self.member.shielded_address()?.nullifier_pubkey;
        wait_for(
            format!("key registry entry of {}", self.member.pubkey()),
            || {
                let root = registry_root(self.ring, rpc)?;
                match (ReadSealedKey {
                    ring: self.ring,
                    member,
                    root,
                })
                .read(indexer)
                {
                    Ok(entry) => {
                        // 1. Indexer metadata alone cannot suppress key
                        // registration.
                        entry.verify_nullifier_pubkey(&nullifier_pubkey)?;
                        Ok(Probe::Ready(true))
                    }
                    Err(KeyRegistrationError::Client(error))
                        if matches!(*error, ClientError::RingKeyRegistryMemberUnregistered) =>
                    {
                        Ok(Probe::Ready(false))
                    }
                    Err(error) if error.is_projection_lag() => {
                        Ok(Probe::Retry(KeyError::from(error)))
                    }
                    Err(error) => Err(KeyError::from(error)),
                }
            },
        )
        .map_err(|error| match error {
            WaitError::Failed(error) => error,
            WaitError::Timeout { label, last } => KeyError::Timeout { label, last },
        })
    }

    fn register<I: Rpc>(
        &self,
        env: TransferProofEnvironment<'_, I, SolanaRpc>,
    ) -> Result<(), KeyError> {
        let rpc = env.rpc;
        let proven = wait_for(
            format!("key registry witness of {}", self.member.pubkey()),
            || {
                let proven = RegisterKey {
                    ring: self.ring,
                    member: self.member,
                }
                .prove(TransferProofEnvironment {
                    indexer: env.indexer,
                    rpc: env.rpc,
                    prover: env.prover,
                });
                match proven {
                    Ok(proven) => Ok(Probe::Ready(proven)),
                    Err(error) if error.is_projection_lag() => Ok(Probe::Retry(error)),
                    Err(error) => Err(error),
                }
            },
        )
        .map_err(timed_out)?;
        IdempotentStep {
            rpc,
            authority: self.member,
            co_signers: &[],
            name: "register_key",
            compute_unit_limit: REGISTER_KEY_COMPUTE_UNIT_LIMIT,
            hint: no_hint,
        }
        .ensure_present(Observed::Absent, &[proven.instruction()?])?;
        Ok(())
    }

    fn member_tag(&self) -> Result<Member, KeyError> {
        Ok(Member::owner_tag(self.member.pubkey().as_array())?)
    }
}

fn timed_out(error: WaitError<KeyRegistrationError>) -> KeyError {
    match error {
        WaitError::Failed(error) => error.into(),
        WaitError::Timeout { label, last } => KeyError::Timeout {
            label,
            last: last.map(|error| Box::new((*error).into())),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use custom_ring_interface::{
        HeadMapLeaf, KeyRegistryRoot, MerklePath, RegisteredKey, HEAD_MAP_HEIGHT, KEY_REGISTRY_ROOT,
    };
    use solana_account::Account;
    use solana_address::Address;
    use zolana_indexer_api::{
        Base64String, Context as RegistryContext, GetRingKeyRegistryEntryResponse, Hash,
        RingMemberProofRequest,
    };
    use zolana_keypair::ViewingKey;

    use crate::ui::{Answer, Scripted};

    use super::*;

    fn ring() -> CustomRing {
        CustomRing::new(solana_address::Address::new_from_array([9; 32]))
    }

    const ROOT: IndexedMapRoot = IndexedMapRoot {
        root: [3u8; 32],
        next_index: 2,
        history_index: 0,
    };

    struct RegistryRpc {
        reads: Cell<u8>,
        advance: bool,
        root: IndexedMapRoot,
    }

    impl RegistryRpc {
        fn fixed() -> Self {
            Self {
                reads: Cell::new(0),
                advance: false,
                root: ROOT,
            }
        }
    }

    impl Rpc for RegistryRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            let (expected, bump) =
                custom_ring_interface::pda::key_registry_root(&ring().program_id());
            assert_eq!(address, expected);
            let reads = self.reads.get();
            self.reads.set(reads + 1);
            let current = if self.advance && reads > 0 {
                [1; 32]
            } else {
                self.root.root
            };
            let mut history = [[0; 32]; custom_ring_interface::KEY_REGISTRY_ROOT_HISTORY];
            history[0] = current;
            let root = KeyRegistryRoot {
                discriminator: KEY_REGISTRY_ROOT,
                root: current,
                next_index: (self.root.next_index + u64::from(self.advance && reads > 0))
                    .to_le_bytes(),
                bump,
                history_cursor: 0,
                history,
            };
            Ok(Some(Account {
                lamports: 1,
                data: bytemuck::bytes_of(&root).to_vec(),
                owner: ring().program_id(),
                executable: false,
                rent_epoch: 0,
            }))
        }
    }

    struct StubIndexer(Option<GetRingKeyRegistryEntryResponse>);

    impl Rpc for StubIndexer {
        fn get_ring_key_registry_entry(
            &self,
            _request: RingMemberProofRequest,
        ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
            self.0
                .clone()
                .ok_or(ClientError::RingKeyRegistryMemberUnregistered)
        }
    }

    struct RegisteredEntry {
        rpc: RegistryRpc,
        indexer: StubIndexer,
    }

    fn registered_entry(member: &ShieldedKeypair) -> RegisteredEntry {
        let envelope = zolana_ring_client::NullifierKeyEnvelope::new(
            &member.nullifier_key,
            &ViewingKey::new().pubkey(),
        )
        .unwrap();
        let member_tag = Member::owner_tag(member.pubkey().as_array()).unwrap();
        let commitment = RegisteredKey {
            nullifier_pk: &envelope.nullifier_pk,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .commitment()
        .unwrap();
        let leaf = HeadMapLeaf {
            member: member_tag.as_bytes(),
            next: &[0; 32],
            nullifier: &commitment,
        }
        .hash()
        .unwrap();
        let proof = vec![[0; 32]; HEAD_MAP_HEIGHT];
        let root = MerklePath {
            index: 1,
            siblings: &proof,
        }
        .root_of(leaf)
        .unwrap();
        let response = GetRingKeyRegistryEntryResponse {
            context: RegistryContext::default(),
            root: Hash(root),
            next_index: 2,
            member: Hash(*member_tag.as_bytes()),
            next: Hash([0; 32]),
            index: 1,
            eph_pk: Base64String(envelope.sealed.eph_pk.as_bytes().to_vec()),
            ciphertext: Base64String(envelope.sealed.ciphertext.to_vec()),
            proof: proof.into_iter().map(Hash).collect(),
        };
        RegisteredEntry {
            rpc: RegistryRpc {
                root: IndexedMapRoot {
                    root,
                    next_index: 2,
                    history_index: 0,
                },
                ..RegistryRpc::fixed()
            },
            indexer: StubIndexer(Some(response)),
        }
    }

    fn member() -> ShieldedKeypair {
        ShieldedKeypair::new_ed25519().expect("keypair")
    }

    #[test]
    fn an_existing_entry_skips_the_seal_without_prompting() {
        let member = member();
        let enrolment = KeyEnrolment {
            ring: ring(),
            member: &member,
        };
        let mut ask = Scripted::new([]);
        let RegisteredEntry { rpc, indexer } = registered_entry(&member);
        let registered = enrolment.registered(&indexer, &rpc).expect("registered");
        assert_eq!(
            enrolment.plan(registered, &mut ask).expect("plan"),
            Plan::AlreadyRegistered
        );
    }

    #[test]
    fn an_unregistered_member_enrolls_only_on_confirmation() {
        let member = member();
        let enrolment = KeyEnrolment {
            ring: ring(),
            member: &member,
        };
        let indexer = StubIndexer(None);
        let registered = enrolment
            .registered(&indexer, &RegistryRpc::fixed())
            .expect("registered");
        let mut yes = Scripted::new([Answer::Yes(true)]);
        assert_eq!(
            enrolment.plan(registered, &mut yes).expect("plan"),
            Plan::Enroll
        );
        let mut no = Scripted::new([Answer::Yes(false)]);
        assert_eq!(
            enrolment.plan(registered, &mut no).expect("plan"),
            Plan::Declined
        );
    }

    #[test]
    fn a_lagging_registry_is_polled_until_it_answers() {
        struct Lagging(std::cell::Cell<u8>);
        impl Rpc for Lagging {
            fn get_ring_key_registry_entry(
                &self,
                _request: RingMemberProofRequest,
            ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
                let calls = self.0.get();
                self.0.set(calls + 1);
                if calls == 0 {
                    return Err(ClientError::RingKeyRegistryOutOfSync);
                }
                Err(ClientError::RingKeyRegistryMemberUnregistered)
            }
        }
        let member = member();
        let enrolment = KeyEnrolment {
            ring: ring(),
            member: &member,
        };
        let indexer = Lagging(std::cell::Cell::new(0));
        assert!(!enrolment
            .registered(&indexer, &RegistryRpc::fixed())
            .expect("registered"));
        assert_eq!(indexer.0.get(), 2);
    }

    #[test]
    fn a_changed_registry_root_is_refetched_before_retrying() {
        struct Advanced(Cell<u8>);
        impl Rpc for Advanced {
            fn get_ring_key_registry_entry(
                &self,
                request: RingMemberProofRequest,
            ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
                let calls = self.0.get();
                self.0.set(calls + 1);
                if calls == 0 {
                    assert_eq!(request.expected_root.0, ROOT.root);
                    assert_eq!(request.expected_next_index, ROOT.next_index);
                    return Err(ClientError::RingKeyRegistryRootChanged);
                }
                assert_eq!(request.expected_root.0, [1; 32]);
                assert_eq!(request.expected_next_index, ROOT.next_index + 1);
                Err(ClientError::RingKeyRegistryMemberUnregistered)
            }
        }
        let member = member();
        let enrolment = KeyEnrolment {
            ring: ring(),
            member: &member,
        };
        let indexer = Advanced(Cell::new(0));
        let rpc = RegistryRpc {
            reads: Cell::new(0),
            advance: true,
            root: ROOT,
        };
        assert!(!enrolment.registered(&indexer, &rpc).expect("registered"));
        assert_eq!(indexer.0.get(), 2);
        assert_eq!(rpc.reads.get(), 2);
    }

    #[test]
    fn forged_inclusion_cannot_skip_key_enrollment() {
        let member = member();
        let enrolment = KeyEnrolment {
            ring: ring(),
            member: &member,
        };
        let mutations: [fn(&mut GetRingKeyRegistryEntryResponse); 3] = [
            |entry| entry.proof[0].0[31] ^= 1,
            |entry| entry.ciphertext.0[31] ^= 1,
            |entry| entry.member.0[31] ^= 1,
        ];
        for mutate in mutations {
            let RegisteredEntry { rpc, mut indexer } = registered_entry(&member);
            mutate(indexer.0.as_mut().unwrap());
            assert!(matches!(
                enrolment.registered(&indexer, &rpc),
                Err(KeyError::Registration(error))
                    if matches!(*error, KeyRegistrationError::InvalidEntryProof)
            ));
        }
    }

    #[test]
    fn an_included_different_nullifier_key_does_not_enroll_the_sender() {
        let member = member();
        let mut different_key = ShieldedKeypair::new_ed25519().unwrap();
        different_key.signing_key = member.signing_key.clone();
        let RegisteredEntry { rpc, indexer } = registered_entry(&different_key);
        let enrolment = KeyEnrolment {
            ring: ring(),
            member: &member,
        };
        assert!(matches!(
            enrolment.registered(&indexer, &rpc),
            Err(KeyError::Registration(error))
                if matches!(*error, KeyRegistrationError::InvalidEntryProof)
        ));
    }

    #[test]
    fn a_transport_failure_is_not_read_as_unregistered() {
        struct Down;
        impl Rpc for Down {
            fn get_ring_key_registry_entry(
                &self,
                _request: RingMemberProofRequest,
            ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
                Err(ClientError::IndexerUnavailable("down".to_owned()))
            }
        }
        let member = member();
        let enrolment = KeyEnrolment {
            ring: ring(),
            member: &member,
        };
        assert!(matches!(
            enrolment.registered(&Down, &RegistryRpc::fixed()),
            Err(KeyError::Registration(error)) if matches!(*error, KeyRegistrationError::Client(_))
        ));
    }
}
