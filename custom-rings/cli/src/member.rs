//! `key`, the sender's nullifier key escrowed in its member record.

use anyhow::{Context as _, Result};
use custom_ring_sdk::{CustomRing, ReadMemberRecord, RegisterKey, RingError, RingOperation};
use solana_signer::Signer;
use zolana_client::{BlockingIndexer, BlockingRpc, ZolanaClient};
use zolana_keypair::ShieldedKeypair;
use zolana_ring_policy::Member;

use crate::{
    controls::NO_MEMBER_REGISTRY, line, transact::SENDER_FEE_BUDGET, wait_for, Context, KeyCommand,
    Probe,
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

/// Registration is once per member, a registered key keeps its seal.
pub(crate) fn ensure_key(ctx: &Context, member: &ShieldedKeypair) -> Result<&'static str> {
    if registered(ctx.ring, &ctx.zolana, member)? {
        return Ok("already registered");
    }
    ctx.submit(registration(ctx.ring, member), member, &[])?;
    Ok("registered")
}

/// A submission, so a registry root another batch moved is proved again.
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

/// Only the sender's key escrowed in its record under the current root counts.
fn registered<R: BlockingRpc, I: BlockingIndexer>(
    ring: CustomRing,
    zolana: &ZolanaClient<R, I>,
    keys: &ShieldedKeypair,
) -> Result<bool> {
    let member = Member::owner_tag(keys.pubkey().as_array())?;
    let nullifier_pubkey = keys.shielded_address()?.nullifier_pubkey;
    wait_for(format_args!("member record of {}", keys.pubkey()), || {
        let root = zolana
            .block_on(ring.member_registry_root(zolana.as_async()))?
            .context(NO_MEMBER_REGISTRY)?;
        let read = ReadMemberRecord { ring, member };
        match zolana.block_on(read.read_at(zolana.as_async(), root)) {
            Ok(record) if record.opening.escrow_key() == [0; 32] => Ok(Probe::Ready(false)),
            Ok(record) => {
                record
                    .sealed_key()
                    .ok_or(RingError::InvalidRecordOpening)?
                    .verify_nullifier_pubkey(&nullifier_pubkey)?;
                Ok(Probe::Ready(true))
            }
            Err(error) if error.is_projection_lag() => Ok(Probe::Retry(error.into())),
            Err(error) => Err(error.into()),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use custom_ring_interface::{
        EscrowKey, MemberRegistryRoot, MEMBER_REGISTRY_ROOT, MEMBER_REGISTRY_ROOT_HISTORY,
    };
    use solana_account::Account;
    use solana_address::Address;
    use zolana_client::{ClientError, ProverClient, Rpc, WitnessReader};
    use zolana_indexer_api::{
        Base64String, Context as RegistryContext, GetRingMemberRecordRequest,
        GetRingMemberRecordResponse, Hash, RingLowRecordView, RingMemberRecordView,
    };
    use zolana_keypair::X25519Secret;
    use zolana_ring_client::{NullifierKeyEnvelope, SealedNullifierKey};
    use zolana_ring_member_registry::{MemberRegistryTree, Opening};

    use super::*;
    use crate::ui::{Answer, Ask, Scripted};

    fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([9; 32]))
    }

    fn empty() -> MemberRegistryTree {
        MemberRegistryTree::new().unwrap()
    }

    /// The indexer's answer for `member` under `tree`'s root at history slot 0.
    fn response(
        tree: &MemberRegistryTree,
        member: &[u8; 32],
        sealed: Option<&SealedNullifierKey>,
    ) -> GetRingMemberRecordResponse {
        let base = GetRingMemberRecordResponse {
            context: RegistryContext::default(),
            root: Hash(tree.root()),
            root_index: 0,
            next_index: tree.next_index(),
            present: false,
            record: None,
            index: 0,
            path: Vec::new(),
            low: None,
        };
        match tree.opening(member).unwrap() {
            Opening::Present {
                record,
                index,
                path,
            } => GetRingMemberRecordResponse {
                present: true,
                record: Some(RingMemberRecordView {
                    member: Hash(record.member),
                    next: Hash(record.next),
                    lists: record.lists,
                    escrow_key: Hash(record.escrow_key),
                    owner_pubkey: None,
                    eph_pk: sealed.map(|key| Base64String(key.eph_pk.as_bytes().to_vec())),
                    ciphertext: sealed.map(|key| Base64String(key.ciphertext.to_vec())),
                }),
                index,
                path: path.into_iter().map(Hash).collect(),
                ..base
            },
            Opening::Absent {
                low,
                low_index,
                path,
            } => GetRingMemberRecordResponse {
                low: Some(RingLowRecordView {
                    member: Hash(low.member),
                    next: Hash(low.next),
                    lists: low.lists,
                    escrow_key: Hash(low.escrow_key),
                    index: low_index,
                    path: path.into_iter().map(Hash).collect(),
                }),
                ..base
            },
        }
    }

    /// Serves the registry root account, the second read sees `advanced` when set.
    struct RegistryRpc {
        reads: AtomicU8,
        tree: MemberRegistryTree,
        advanced: Option<MemberRegistryTree>,
    }

    impl RegistryRpc {
        fn of(tree: MemberRegistryTree) -> Self {
            Self {
                reads: AtomicU8::new(0),
                tree,
                advanced: None,
            }
        }
    }

    impl Rpc for RegistryRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            let (expected, bump) =
                Address::find_program_address(&[MemberRegistryRoot::SEED], &ring().program_id());
            assert_eq!(address, expected);
            let reads = self.reads.fetch_add(1, Ordering::Relaxed);
            let tree = match &self.advanced {
                Some(advanced) if reads > 0 => advanced,
                _ => &self.tree,
            };
            let mut history = [[0; 32]; MEMBER_REGISTRY_ROOT_HISTORY];
            history[0] = tree.root();
            let root = MemberRegistryRoot {
                discriminator: MEMBER_REGISTRY_ROOT,
                next_index: tree.next_index().to_le_bytes(),
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

    struct StubIndexer(GetRingMemberRecordResponse);

    impl WitnessReader for StubIndexer {}

    impl Rpc for StubIndexer {
        fn get_ring_member_record(
            &self,
            _request: GetRingMemberRecordRequest,
        ) -> Result<GetRingMemberRecordResponse, ClientError> {
            Ok(self.0.clone())
        }
    }

    fn zolana<I: Rpc + WitnessReader + Send + Sync + 'static>(
        rpc: RegistryRpc,
        indexer: I,
    ) -> ZolanaClient<RegistryRpc, I> {
        ZolanaClient::new(rpc, indexer, ProverClient::local())
    }

    fn member_tag(member: &ShieldedKeypair) -> [u8; 32] {
        *Member::owner_tag(member.pubkey().as_array())
            .unwrap()
            .as_bytes()
    }

    /// `key_holder`'s nullifier key escrowed in `member`'s record.
    fn registered_record(
        member: &ShieldedKeypair,
        key_holder: &ShieldedKeypair,
    ) -> (RegistryRpc, StubIndexer) {
        let envelope =
            NullifierKeyEnvelope::new(&key_holder.nullifier_key, &X25519Secret::new().pubkey())
                .unwrap();
        let escrow_key = EscrowKey {
            nullifier_pk: &envelope.nullifier_pk,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .hash()
        .unwrap();
        let mut tree = empty();
        let item = tree.register_item(&member_tag(member), escrow_key).unwrap();
        tree.apply(&[item]).unwrap();
        let answer = response(&tree, &member_tag(member), Some(&envelope.sealed));
        (RegistryRpc::of(tree), StubIndexer(answer))
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
    fn a_registered_key_skips_the_seal_without_prompting() {
        let member = member();
        let (rpc, indexer) = registered_record(&member, &member);
        let registered = registered(ring(), &zolana(rpc, indexer), &member).expect("registered");
        let plan = plan(registered, || panic!("an enrolled member is not asked"));
        assert_eq!(plan.expect("plan"), Plan::AlreadyRegistered);
    }

    #[test]
    fn an_unregistered_member_enrolls_only_on_confirmation() {
        let member = member();
        let absent = response(&empty(), &member_tag(&member), None);
        let client = zolana(RegistryRpc::of(empty()), StubIndexer(absent));
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
    }

    #[test]
    fn a_lagging_registry_is_polled_until_it_answers() {
        struct Lagging(AtomicU8, GetRingMemberRecordResponse);
        impl WitnessReader for Lagging {}
        impl Rpc for Lagging {
            fn get_ring_member_record(
                &self,
                _request: GetRingMemberRecordRequest,
            ) -> Result<GetRingMemberRecordResponse, ClientError> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    return Err(ClientError::RingRegistryOutOfSync);
                }
                Ok(self.1.clone())
            }
        }
        let member = member();
        let absent = response(&empty(), &member_tag(&member), None);
        let client = zolana(RegistryRpc::of(empty()), Lagging(AtomicU8::new(0), absent));
        assert!(!registered(ring(), &client, &member).expect("registered"));
        assert_eq!(client.indexer().0.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_changed_registry_root_is_refetched_before_retrying() {
        struct Advanced(AtomicU8, [u8; 32], GetRingMemberRecordResponse);
        impl WitnessReader for Advanced {}
        impl Rpc for Advanced {
            fn get_ring_member_record(
                &self,
                request: GetRingMemberRecordRequest,
            ) -> Result<GetRingMemberRecordResponse, ClientError> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    assert_eq!(request.expected_root.0, self.1);
                    return Err(ClientError::RingRegistryRootChanged);
                }
                assert_eq!(request.expected_root.0, self.2.root.0);
                Ok(self.2.clone())
            }
        }
        let member = member();
        let mut advanced = empty();
        let other = *Member::owner_tag(&[5; 32]).unwrap().as_bytes();
        advanced
            .apply(&advanced.list_items(&[(other, 1)]).unwrap())
            .unwrap();
        let answer = response(&advanced, &member_tag(&member), None);
        let rpc = RegistryRpc {
            advanced: Some(advanced),
            ..RegistryRpc::of(empty())
        };
        let first = empty().root();
        let client = zolana(rpc, Advanced(AtomicU8::new(0), first, answer));
        assert!(!registered(ring(), &client, &member).expect("registered"));
        assert_eq!(client.indexer().0.load(Ordering::Relaxed), 2);
        assert_eq!(client.rpc().reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_forged_record_cannot_skip_key_enrollment() {
        let member = member();
        let mutations: [fn(&mut GetRingMemberRecordResponse); 3] = [
            |record| record.path[0].0[31] ^= 1,
            |record| {
                record
                    .record
                    .as_mut()
                    .unwrap()
                    .ciphertext
                    .as_mut()
                    .unwrap()
                    .0[31] ^= 1
            },
            |record| record.record.as_mut().unwrap().member.0[31] ^= 1,
        ];
        for mutate in mutations {
            let (rpc, mut indexer) = registered_record(&member, &member);
            mutate(&mut indexer.0);
            assert!(matches!(
                ring_error(registered(ring(), &zolana(rpc, indexer), &member)),
                RingError::InvalidRecordOpening
            ));
        }
    }

    #[test]
    fn another_escrowed_nullifier_key_does_not_enroll_the_sender() {
        let member = member();
        let mut different_key = ShieldedKeypair::new_ed25519().unwrap();
        different_key.signing_key = member.signing_key.clone();
        let (rpc, indexer) = registered_record(&member, &different_key);
        assert!(matches!(
            ring_error(registered(ring(), &zolana(rpc, indexer), &member)),
            RingError::InvalidRecordOpening
        ));
    }

    #[test]
    fn a_transport_failure_is_not_read_as_unregistered() {
        struct Down;
        impl WitnessReader for Down {}
        impl Rpc for Down {
            fn get_ring_member_record(
                &self,
                _request: GetRingMemberRecordRequest,
            ) -> Result<GetRingMemberRecordResponse, ClientError> {
                Err(ClientError::IndexerUnavailable("down".to_owned()))
            }
        }
        assert!(matches!(
            ring_error(registered(
                ring(),
                &zolana(RegistryRpc::of(empty()), Down),
                &member()
            )),
            RingError::Client(_)
        ));
    }
}
