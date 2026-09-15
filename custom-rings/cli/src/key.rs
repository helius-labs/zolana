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
    pub root: IndexedMapRoot,
}

pub fn run(ctx: &mut Context, command: KeyCommand) -> Result<(), KeyError> {
    let sender = sender_keypair_file(ctx)?;
    match command {
        KeyCommand::Register => {
            let member = ShieldedKeypair::from_keypair(&sender)?;
            let enrolment = KeyEnrolment {
                ring: ctx.ring,
                member: &member,
                root: registry_root(ctx.ring, &ctx.rpc)?,
            };
            let indexer = ctx.indexer();
            line("member", sender.pubkey());
            match enrolment.plan(&indexer, ctx.ask.as_mut())? {
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
        if self.registered(env.indexer)? {
            return Ok(KeyOutcome::Present);
        }
        self.register(env)?;
        Ok(KeyOutcome::Registered)
    }

    fn plan(&self, indexer: &impl Rpc, ask: &mut dyn Ask) -> Result<Plan, KeyError> {
        if self.registered(indexer)? {
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

    /// Only an entry under the current root counts, a lagging Photon is waited out.
    fn registered(&self, indexer: &impl Rpc) -> Result<bool, KeyError> {
        let member = self.member_tag()?;
        wait_for(
            format!("key registry entry of {}", self.member.pubkey()),
            || match (ReadSealedKey {
                ring: self.ring,
                member,
                root: self.root,
            })
            .read(indexer)
            {
                Ok(_) => Ok(Probe::Ready(true)),
                Err(KeyRegistrationError::Client(error))
                    if matches!(*error, ClientError::RingKeyRegistryMemberUnregistered) =>
                {
                    Ok(Probe::Ready(false))
                }
                Err(error) if is_key_registry_retryable(&error) => Ok(Probe::Retry(error)),
                Err(error) => Err(error),
            },
        )
        .map_err(timed_out)
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
                    Err(error) if is_key_registry_retryable(&error) => Ok(Probe::Retry(error)),
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

fn is_key_registry_retryable(error: &KeyRegistrationError) -> bool {
    matches!(error, KeyRegistrationError::Client(error) if matches!(
        error.as_ref(),
        ClientError::RingKeyRegistryOutOfSync | ClientError::RingKeyRegistryRootChanged
    ))
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
    use custom_ring_interface::HEAD_MAP_HEIGHT;
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
        root: [0u8; 32],
        next_index: 2,
    };

    struct StubIndexer {
        registered: bool,
    }

    impl Rpc for StubIndexer {
        fn get_ring_key_registry_entry(
            &self,
            request: RingMemberProofRequest,
        ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
            if !self.registered {
                return Err(ClientError::RingKeyRegistryMemberUnregistered);
            }
            Ok(GetRingKeyRegistryEntryResponse {
                context: RegistryContext::default(),
                root: request.expected_root,
                next_index: request.expected_next_index,
                member: request.member,
                next: Hash([0u8; 32]),
                index: 1,
                eph_pk: Base64String(ViewingKey::new().pubkey().as_bytes().to_vec()),
                ciphertext: Base64String(vec![0u8; 32]),
                proof: vec![Hash([0u8; 32]); HEAD_MAP_HEIGHT],
            })
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
            root: ROOT,
        };
        let mut ask = Scripted::new([]);
        assert_eq!(
            enrolment
                .plan(&StubIndexer { registered: true }, &mut ask)
                .expect("plan"),
            Plan::AlreadyRegistered
        );
    }

    #[test]
    fn an_unregistered_member_enrolls_only_on_confirmation() {
        let member = member();
        let enrolment = KeyEnrolment {
            ring: ring(),
            member: &member,
            root: ROOT,
        };
        let indexer = StubIndexer { registered: false };
        let mut yes = Scripted::new([Answer::Yes(true)]);
        assert_eq!(
            enrolment.plan(&indexer, &mut yes).expect("plan"),
            Plan::Enroll
        );
        let mut no = Scripted::new([Answer::Yes(false)]);
        assert_eq!(
            enrolment.plan(&indexer, &mut no).expect("plan"),
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
            root: ROOT,
        };
        let indexer = Lagging(std::cell::Cell::new(0));
        assert!(!enrolment.registered(&indexer).expect("registered"));
        assert_eq!(indexer.0.get(), 2);
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
            root: ROOT,
        };
        let mut ask = Scripted::new([]);
        assert!(matches!(
            enrolment.plan(&Down, &mut ask),
            Err(KeyError::Registration(error)) if matches!(*error, KeyRegistrationError::Client(_))
        ));
    }
}
