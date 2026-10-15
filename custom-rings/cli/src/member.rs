//! `key` and `spend`, the sender's nullifier key in the ring key registry and its spend record.

use anyhow::{Context as _, Result};
use custom_ring_sdk::{
    CustomRing, LiveSpendRecord, PolicyConfig, ReadSealedKey, ReadSpendRecord, RegisterKey,
    RegisterSpend, RingError, RingOperation,
};
use solana_signer::Signer;
use zolana_client::{BlockingIndexer, BlockingRpc, ClientError, ZolanaClient};
use zolana_keypair::ShieldedKeypair;
use zolana_ring_policy::Member;

use crate::{
    controls::NO_KEY_REGISTRY,
    line,
    transact::SENDER_FEE_BUDGET,
    ui::{self, icon},
    wait_for, Context, KeyCommand, Probe, SpendCommand,
};

const SEAL_PROMPT: &str = "seal the member key to the ring auditor and register it?";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    AlreadyRegistered,
    Enroll,
    Declined,
}

pub fn key(ctx: &Context, command: KeyCommand) -> Result<()> {
    let KeyCommand::Register = command;
    let sender = ctx.sender()?;
    let member = ShieldedKeypair::from_keypair(&sender)?;
    line("member", sender.pubkey());
    let registered = registered(ctx.ring, &ctx.zolana, &member)?;
    match plan(registered, || ctx.ask_yes(SEAL_PROMPT, true))? {
        Plan::AlreadyRegistered => line("key", "already registered"),
        Plan::Declined => line("key", "not registered"),
        Plan::Enroll => {
            ctx.fund(sender.pubkey(), SENDER_FEE_BUDGET)?;
            ctx.submit(registration(ctx.ring, &member), &member, &[])?;
            line("key", "registered");
        }
    }
    Ok(())
}

/// Registration is once per member, an existing entry keeps its seal.
pub(crate) fn ensure_key(ctx: &Context, member: &ShieldedKeypair) -> Result<&'static str> {
    if registered(ctx.ring, &ctx.zolana, member)? {
        return Ok("already registered");
    }
    ctx.submit(registration(ctx.ring, member), member, &[])?;
    Ok("registered")
}

/// A submission, so a registry root another member moved is proved again.
fn registration(ring: CustomRing, member: &ShieldedKeypair) -> RingOperation<'_> {
    RegisterKey { ring, member }.into()
}

fn plan(registered: bool, confirm: impl FnOnce() -> Result<bool>) -> Result<Plan> {
    Ok(match registered {
        true => Plan::AlreadyRegistered,
        false if confirm()? => Plan::Enroll,
        false => Plan::Declined,
    })
}

/// Only the sender's key included under the current root counts, indexer metadata alone does not.
fn registered<R: BlockingRpc, I: BlockingIndexer>(
    ring: CustomRing,
    zolana: &ZolanaClient<R, I>,
    keys: &ShieldedKeypair,
) -> Result<bool> {
    let member = Member::owner_tag(keys.pubkey().as_array())?;
    let nullifier_pubkey = keys.shielded_address()?.nullifier_pubkey;
    wait_for(
        format_args!("key registry entry of {}", keys.pubkey()),
        || {
            let root = zolana
                .block_on(ring.key_registry_root(zolana.as_async()))?
                .context(NO_KEY_REGISTRY)?;
            let read = ReadSealedKey { ring, member, root };
            match zolana.block_on(read.read(zolana.as_async())) {
                Ok(entry) => {
                    entry.verify_nullifier_pubkey(&nullifier_pubkey)?;
                    Ok(Probe::Ready(true))
                }
                Err(RingError::Client(ClientError::RingKeyRegistryMemberUnregistered)) => {
                    Ok(Probe::Ready(false))
                }
                Err(error) if error.is_projection_lag() => Ok(Probe::Retry(error.into())),
                Err(error) => Err(error.into()),
            }
        },
    )
}

pub fn spend(ctx: &Context, command: SpendCommand) -> Result<()> {
    let sender = ctx.sender()?;
    let pinned = ctx
        .block(ctx.ring.pinned_policy(ctx.chain()))?
        .context("the ring has no policy config, run `zolana-ring init` first")?;
    anyhow::ensure!(
        pinned.table.window_slots() != 0,
        "the ring has no velocity window, nothing to register"
    );
    match command {
        SpendCommand::Register => {
            ctx.fund(sender.pubkey(), SENDER_FEE_BUDGET)?;
            let outcome = ensure_spend(ctx, &sender, &pinned.config)?;
            line("member", sender.pubkey());
            line("record", outcome);
        }
        SpendCommand::Show => {
            let member = Member::owner_tag(sender.pubkey().as_array())?;
            let live = spend_record(ctx, &pinned.config, member)?;
            let title = format!("spend record of {}", sender.pubkey());
            ui::heading(icon::POLICY, &title);
            match live {
                None => line("record", "not registered"),
                Some(live) => {
                    line("version", live.record.version);
                    line("window", live.record.window);
                    line("commitment", hex::encode(live.record.counters_commitment));
                }
            }
        }
    }
    Ok(())
}

/// The record is claimed once with zero counters, an existing record is kept.
pub(crate) fn ensure_spend(
    ctx: &Context,
    sender: &(dyn Signer + Sync),
    config: &PolicyConfig,
) -> Result<String> {
    let member = Member::owner_tag(sender.pubkey().as_array())?;
    if let Some(live) = spend_record(ctx, config, member)? {
        return Ok(format!(
            "already registered at version {}",
            live.record.version
        ));
    }
    ctx.submit(spend_registration(ctx.ring, sender), sender, &[])?;
    wait_for(format_args!("spend record of {}", sender.pubkey()), || {
        Ok(match spend_record(ctx, config, member)? {
            Some(_) => Probe::Ready(()),
            None => Probe::NotYet,
        })
    })?;
    Ok("registered".to_owned())
}

/// A submission, so a window that closes before the proof lands is proved again.
fn spend_registration(ring: CustomRing, sender: &(dyn Signer + Sync)) -> RingOperation<'static> {
    RegisterSpend {
        ring,
        payer: sender.pubkey(),
    }
    .into()
}

fn spend_record(
    ctx: &Context,
    config: &PolicyConfig,
    member: Member,
) -> Result<Option<LiveSpendRecord>> {
    let read = ReadSpendRecord::new(ctx.ring, config.address_tree_id(), member);
    Ok(ctx.block(read.read_current(ctx.chain()))?)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use custom_ring_interface::{
        KeyRegistryLeaf, KeyRegistryRoot, MerklePath, RegisteredKey, KEY_REGISTRY_HEIGHT,
        KEY_REGISTRY_ROOT,
    };
    use custom_ring_sdk::CurrentKeyRegistryRoot;
    use solana_account::Account;
    use solana_address::Address;
    use zolana_client::{ProverClient, Rpc, WitnessReader};
    use zolana_indexer_api::{
        Base64String, Context as RegistryContext, GetRingKeyRegistryEntryResponse, Hash,
        RingMemberProofRequest,
    };
    use zolana_keypair::ViewingKey;

    use super::*;
    use crate::ui::{Answer, Ask, Scripted};

    fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([9; 32]))
    }

    const ROOT: CurrentKeyRegistryRoot = CurrentKeyRegistryRoot {
        root: [3u8; 32],
        next_index: 2,
        history_index: 0,
    };

    struct RegistryRpc {
        reads: AtomicU8,
        advance: bool,
        root: CurrentKeyRegistryRoot,
    }

    impl RegistryRpc {
        fn fixed() -> Self {
            Self {
                reads: AtomicU8::new(0),
                advance: false,
                root: ROOT,
            }
        }
    }

    impl Rpc for RegistryRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            let (expected, bump) =
                Address::find_program_address(&[KeyRegistryRoot::SEED], &ring().program_id());
            assert_eq!(address, expected);
            let reads = self.reads.fetch_add(1, Ordering::Relaxed);
            let advanced = self.advance && reads > 0;
            let mut history = [[0; 32]; custom_ring_interface::KEY_REGISTRY_ROOT_HISTORY];
            history[0] = if advanced { [1; 32] } else { self.root.root };
            let root = KeyRegistryRoot {
                discriminator: KEY_REGISTRY_ROOT,
                next_index: (self.root.next_index + u64::from(advanced)).to_le_bytes(),
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

    impl WitnessReader for StubIndexer {}

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

    fn zolana<I: Rpc + WitnessReader + Send + Sync + 'static>(
        rpc: RegistryRpc,
        indexer: I,
    ) -> ZolanaClient<RegistryRpc, I> {
        ZolanaClient::new(rpc, indexer, ProverClient::local())
    }

    fn registered_entry(member: &ShieldedKeypair) -> (RegistryRpc, StubIndexer) {
        let envelope = zolana_ring_client::NullifierKeyEnvelope::new(
            &member.nullifier_key,
            &ViewingKey::new().pubkey(),
        )
        .unwrap();
        let member_tag = Member::owner_tag(member.pubkey().as_array()).unwrap();
        let key = RegisteredKey {
            nullifier_pk: &envelope.nullifier_pk,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .hash()
        .unwrap();
        let leaf = KeyRegistryLeaf {
            member: member_tag.as_bytes(),
            next: &[0; 32],
            key: &key,
        }
        .hash()
        .unwrap();
        let proof = vec![[0; 32]; KEY_REGISTRY_HEIGHT];
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
        let rpc = RegistryRpc {
            root: CurrentKeyRegistryRoot {
                root,
                next_index: 2,
                history_index: 0,
            },
            ..RegistryRpc::fixed()
        };
        (rpc, StubIndexer(Some(response)))
    }

    fn member() -> ShieldedKeypair {
        ShieldedKeypair::new_ed25519().expect("keypair")
    }

    fn ring_error(result: Result<bool>) -> RingError {
        let error = result.expect_err("refused");
        match error.downcast::<RingError>() {
            Ok(error) => error,
            Err(error) => panic!("not a ring error: {error:?}"),
        }
    }

    #[test]
    fn an_existing_entry_skips_the_seal_without_prompting() {
        let member = member();
        let (rpc, indexer) = registered_entry(&member);
        let registered = registered(ring(), &zolana(rpc, indexer), &member).expect("registered");
        let plan = plan(registered, || panic!("an enrolled member is not asked"));
        assert_eq!(plan.expect("plan"), Plan::AlreadyRegistered);
    }

    #[test]
    fn an_unregistered_member_enrolls_only_on_confirmation() {
        let member = member();
        let client = zolana(RegistryRpc::fixed(), StubIndexer(None));
        let registered = registered(ring(), &client, &member).expect("registered");
        let mut yes = Scripted::new([Answer::Yes(true)]);
        assert_eq!(
            plan(registered, || yes.confirm(SEAL_PROMPT, true)).expect("plan"),
            Plan::Enroll
        );
        let mut no = Scripted::new([Answer::Yes(false)]);
        assert_eq!(
            plan(registered, || no.confirm(SEAL_PROMPT, true)).expect("plan"),
            Plan::Declined
        );
    }

    #[test]
    fn registrations_go_through_the_retrying_submission() {
        let member = member();
        assert!(matches!(
            registration(ring(), &member),
            RingOperation::RegisterKey(_)
        ));
        assert!(matches!(
            spend_registration(ring(), &member),
            RingOperation::RegisterSpend(_)
        ));
    }

    #[test]
    fn a_lagging_registry_is_polled_until_it_answers() {
        struct Lagging(AtomicU8);
        impl WitnessReader for Lagging {}
        impl Rpc for Lagging {
            fn get_ring_key_registry_entry(
                &self,
                _request: RingMemberProofRequest,
            ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    return Err(ClientError::RingKeyRegistryOutOfSync);
                }
                Err(ClientError::RingKeyRegistryMemberUnregistered)
            }
        }
        let client = zolana(RegistryRpc::fixed(), Lagging(AtomicU8::new(0)));
        assert!(!registered(ring(), &client, &member()).expect("registered"));
        assert_eq!(client.indexer().0.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_changed_registry_root_is_refetched_before_retrying() {
        struct Advanced(AtomicU8);
        impl WitnessReader for Advanced {}
        impl Rpc for Advanced {
            fn get_ring_key_registry_entry(
                &self,
                request: RingMemberProofRequest,
            ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    assert_eq!(request.expected_root.0, ROOT.root);
                    assert_eq!(request.expected_next_index, ROOT.next_index);
                    return Err(ClientError::RingKeyRegistryRootChanged);
                }
                assert_eq!(request.expected_root.0, [1; 32]);
                assert_eq!(request.expected_next_index, ROOT.next_index + 1);
                Err(ClientError::RingKeyRegistryMemberUnregistered)
            }
        }
        let rpc = RegistryRpc {
            advance: true,
            ..RegistryRpc::fixed()
        };
        let client = zolana(rpc, Advanced(AtomicU8::new(0)));
        assert!(!registered(ring(), &client, &member()).expect("registered"));
        assert_eq!(client.indexer().0.load(Ordering::Relaxed), 2);
        assert_eq!(client.rpc().reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn forged_inclusion_cannot_skip_key_enrollment() {
        let member = member();
        let mutations: [fn(&mut GetRingKeyRegistryEntryResponse); 3] = [
            |entry| entry.proof[0].0[31] ^= 1,
            |entry| entry.ciphertext.0[31] ^= 1,
            |entry| entry.member.0[31] ^= 1,
        ];
        for mutate in mutations {
            let (rpc, mut indexer) = registered_entry(&member);
            mutate(indexer.0.as_mut().unwrap());
            assert!(matches!(
                ring_error(registered(ring(), &zolana(rpc, indexer), &member)),
                RingError::InvalidEntryProof
            ));
        }
    }

    #[test]
    fn an_included_different_nullifier_key_does_not_enroll_the_sender() {
        let member = member();
        let mut different_key = ShieldedKeypair::new_ed25519().unwrap();
        different_key.signing_key = member.signing_key.clone();
        let (rpc, indexer) = registered_entry(&different_key);
        assert!(matches!(
            ring_error(registered(ring(), &zolana(rpc, indexer), &member)),
            RingError::InvalidEntryProof
        ));
    }

    #[test]
    fn a_transport_failure_is_not_read_as_unregistered() {
        struct Down;
        impl WitnessReader for Down {}
        impl Rpc for Down {
            fn get_ring_key_registry_entry(
                &self,
                _request: RingMemberProofRequest,
            ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
                Err(ClientError::IndexerUnavailable("down".to_owned()))
            }
        }
        assert!(matches!(
            ring_error(registered(
                ring(),
                &zolana(RegistryRpc::fixed(), Down),
                &member()
            )),
            RingError::Client(_)
        ));
    }
}
