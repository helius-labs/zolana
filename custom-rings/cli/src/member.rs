//! `key`, the member's nullifier key escrowed in its record.

use anyhow::{ensure, Result};
use custom_ring_sdk::{CustomRing, MemberRecords, RegisterKey, RingMode, RingOperation};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::{BlockingIndexer, BlockingRpc, ZolanaClient};
use zolana_keypair::ShieldedKeypair;
use zolana_ring_policy::Member;

use crate::{
    fund::{TopUp, MIN_AUTHORITY_BALANCE},
    line,
    records::{self, write_budget, PendingWrites, Queued, Stage},
    transact::SENDER_FEE_BUDGET,
    Context, KeyCommand,
};

const SEAL_PROMPT: &str = "seal the member key to the ring auditor and register it?";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    AlreadyRegistered,
    AlreadyQueued,
    Enroll,
    Declined,
}

/// One application after the last registration opens every escrow.
#[must_use]
pub(crate) struct KeyEnrolment<'a> {
    pub funder: &'a Keypair,
    pub members: &'a [&'a ShieldedKeypair],
}

pub fn key(ctx: &Context, command: KeyCommand) -> Result<()> {
    let KeyCommand::Register = command;
    let config = ctx.ring_config()?;
    ensure!(
        config.mode != RingMode::Anonymous,
        "an anonymous ring escrows no key, its auditor opens every note"
    );
    let sender = ctx.sender()?;
    let member = ShieldedKeypair::from_keypair(&sender)?;
    line("member", sender.pubkey());
    let queued = match plan(key_stage(ctx, &member)?, || ctx.ask_yes(SEAL_PROMPT, true))? {
        Plan::AlreadyRegistered => {
            line("key", "already registered");
            return Ok(());
        }
        Plan::Declined => {
            line("key", "not registered");
            return Ok(());
        }
        Plan::AlreadyQueued => {
            line("key", "already queued");
            ctx.fund(sender.pubkey(), SENDER_FEE_BUDGET)?;
            Queued::now(&ctx.zolana, ctx.ring)?
        }
        Plan::Enroll => {
            ctx.fund(sender.pubkey(), write_budget(&config, &sender.pubkey()))?;
            let queued = register(ctx, &member)?;
            line("key", "registered");
            queued
        }
    };
    queued.apply(&ctx.zolana, &member)?;
    line("queue", "applied");
    Ok(())
}

impl KeyEnrolment<'_> {
    pub(crate) fn ensure(self, ctx: &Context) -> Result<()> {
        let funder = self.funder;
        if let Some(queued) = self.queue(ctx)? {
            queued.apply(&ctx.zolana, funder)?;
            line("member keys", "applied");
        }
        Ok(())
    }

    /// `None` when every member already escrows its key.
    pub(crate) fn queue(self, ctx: &Context) -> Result<Option<Queued>> {
        let config = ctx.ring_config()?;
        let stages = self
            .members
            .iter()
            .map(|member| key_stage(ctx, member))
            .collect::<Result<Vec<_>>>()?;
        let top_ups = self
            .members
            .iter()
            .zip(&stages)
            .filter(|(_, stage)| **stage == Stage::Unsent)
            .map(|(member, _)| write_budget(&config, &member.pubkey()))
            .fold(MIN_AUTHORITY_BALANCE, u64::saturating_add);
        ctx.fund(self.funder.pubkey(), top_ups)?;
        let mut queued = None;
        for (member, stage) in self.members.iter().zip(stages) {
            let outcome = match stage {
                Stage::Applied => "already registered",
                Stage::Queued => {
                    queued = Some(Queued::now(&ctx.zolana, ctx.ring)?);
                    "already queued"
                }
                Stage::Unsent => {
                    TopUp {
                        funder: self.funder,
                        who: member.pubkey(),
                        lamports: write_budget(&config, &member.pubkey()),
                    }
                    .send(ctx)?;
                    queued = Some(register(ctx, member)?);
                    "registered"
                }
            };
            line("member key", format_args!("{} {outcome}", member.pubkey()));
        }
        Ok(queued)
    }
}

fn register(ctx: &Context, member: &ShieldedKeypair) -> Result<Queued> {
    ctx.submit(registration(ctx.ring, member)?, member, &[])?;
    Queued::now(&ctx.zolana, ctx.ring)
}

/// A submission, so a registry root another batch moved is proved again.
fn registration(ring: CustomRing, member: &ShieldedKeypair) -> Result<RingOperation<'_>> {
    Ok(RegisterKey {
        ring,
        member: member.shielded_address()?,
        payer: member.pubkey(),
        authority: member,
    }
    .into())
}

fn plan(stage: Stage, confirm: impl FnOnce() -> Result<bool>) -> Result<Plan> {
    Ok(match stage {
        Stage::Applied => Plan::AlreadyRegistered,
        Stage::Queued => Plan::AlreadyQueued,
        Stage::Unsent if confirm()? => Plan::Enroll,
        Stage::Unsent => Plan::Declined,
    })
}

fn key_stage(ctx: &Context, keys: &ShieldedKeypair) -> Result<Stage> {
    let pending = PendingWrites::read(ctx)?;
    if registered(ctx.ring, &ctx.zolana, keys)? {
        return Ok(Stage::Applied);
    }
    let member = Member::owner_tag(keys.pubkey().as_array())?;
    Ok(match pending.registers(&member) {
        true => Stage::Queued,
        false => Stage::Unsent,
    })
}

/// Only the member's own nullifier key escrowed under the current root counts.
fn registered<R: BlockingRpc, I: BlockingIndexer>(
    ring: CustomRing,
    zolana: &ZolanaClient<R, I>,
    keys: &ShieldedKeypair,
) -> Result<bool> {
    let member = Member::owner_tag(keys.pubkey().as_array())?;
    let read = records::read_one(
        zolana,
        MemberRecords {
            ring,
            members: &[member],
        },
    )?;
    let nullifier_pubkey = keys.shielded_address()?.nullifier_pubkey;
    Ok(read.escrowed(&nullifier_pubkey)?.is_some())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use custom_ring_interface::{EscrowKey, QueueEntry};
    use custom_ring_sdk::RingError;
    use zolana_client::{ClientError, GetRingMemberOpeningsRequest, Rpc, WitnessReader};
    use zolana_indexer_api::RingMemberOpening;
    use zolana_keypair::X25519Keypair;
    use zolana_ring_client::{AuditError, NullifierKeyEnvelope};
    use zolana_ring_member_registry::MemberRegistryTree;

    use super::*;
    use crate::{
        records::fixtures::{ring, tree, zolana, IndexerAnswer, RegistryRpc},
        ui::{Answer, Ask, Scripted},
    };

    fn member() -> ShieldedKeypair {
        ShieldedKeypair::new_ed25519().expect("keypair")
    }

    fn identity(member: &ShieldedKeypair) -> [u8; 32] {
        *Member::owner_tag(member.pubkey().as_array())
            .unwrap()
            .as_bytes()
    }

    struct Stub(zolana_client::GetRingMemberOpeningsResponse);

    impl WitnessReader for Stub {}

    impl Rpc for Stub {
        fn get_ring_member_openings(
            &self,
            _request: GetRingMemberOpeningsRequest,
        ) -> Result<zolana_client::GetRingMemberOpeningsResponse, ClientError> {
            Ok(self.0.clone())
        }
    }

    /// `key_holder`'s nullifier key escrowed in `member`'s record.
    struct Escrowed<'a> {
        member: &'a ShieldedKeypair,
        key_holder: &'a ShieldedKeypair,
    }

    struct Served {
        rpc: RegistryRpc,
        indexer: Stub,
    }

    impl Escrowed<'_> {
        fn served(self) -> Served {
            let envelope = NullifierKeyEnvelope::new(
                &self.key_holder.nullifier_key,
                &X25519Keypair::new().pubkey(),
            )
            .unwrap();
            let escrow = EscrowKey {
                nullifier_pk: &envelope.nullifier_pk,
                ciphertext: &envelope.sealed.ciphertext,
            };
            let member = identity(self.member);
            let tree = tree(&[QueueEntry::escrow(member, &escrow).unwrap()]);
            let answer = IndexerAnswer {
                tree: &tree,
                member: &member,
                sealed: Some(&envelope.sealed),
            }
            .openings();
            Served {
                rpc: RegistryRpc::of(tree),
                indexer: Stub(answer),
            }
        }
    }

    impl Served {
        fn registered(self, member: &ShieldedKeypair) -> Result<bool> {
            registered(ring(), &zolana(self.rpc, self.indexer), member)
        }
    }

    fn ring_error(result: Result<bool>) -> RingError {
        match result.expect_err("refused").downcast::<RingError>() {
            Ok(error) => error,
            Err(error) => panic!("not a ring error: {error:?}"),
        }
    }

    #[test]
    fn a_registered_key_skips_the_seal_without_prompting() {
        let member = member();
        let served = Escrowed {
            member: &member,
            key_holder: &member,
        }
        .served();
        assert!(served.registered(&member).expect("registered"));
        let plan = plan(Stage::Applied, || panic!("an enrolled member is not asked"));
        assert_eq!(plan.expect("plan"), Plan::AlreadyRegistered);
    }

    #[test]
    fn a_queued_registration_is_neither_asked_for_nor_sent_again() {
        let plan = plan(Stage::Queued, || {
            panic!("a queued registration is not asked")
        });
        assert_eq!(plan.expect("plan"), Plan::AlreadyQueued);
    }

    #[test]
    fn an_unregistered_member_enrolls_only_on_confirmation() {
        let member = member();
        let empty = MemberRegistryTree::new().unwrap();
        let absent = IndexerAnswer {
            tree: &empty,
            member: &identity(&member),
            sealed: None,
        }
        .openings();
        let client = zolana(RegistryRpc::of(empty), Stub(absent));
        assert!(!registered(ring(), &client, &member).expect("registered"));
        let mut yes = Scripted::new([Answer::Yes(true)]);
        assert_eq!(
            plan(Stage::Unsent, || yes.confirm(SEAL_PROMPT, true)).expect("plan"),
            Plan::Enroll
        );
        let mut no = Scripted::new([Answer::Yes(false)]);
        assert_eq!(
            plan(Stage::Unsent, || no.confirm(SEAL_PROMPT, true)).expect("plan"),
            Plan::Declined
        );
    }

    #[test]
    fn registrations_go_through_the_retrying_submission() {
        let member = member();
        assert!(matches!(
            registration(ring(), &member).unwrap(),
            RingOperation::RegisterKey(_)
        ));
    }

    #[test]
    fn a_lagging_registry_is_polled_until_it_answers() {
        struct Lagging(AtomicU8, zolana_client::GetRingMemberOpeningsResponse);
        impl WitnessReader for Lagging {}
        impl Rpc for Lagging {
            fn get_ring_member_openings(
                &self,
                _request: GetRingMemberOpeningsRequest,
            ) -> Result<zolana_client::GetRingMemberOpeningsResponse, ClientError> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    return Err(ClientError::RingRegistryOutOfSync);
                }
                Ok(self.1.clone())
            }
        }
        let member = member();
        let empty = MemberRegistryTree::new().unwrap();
        let absent = IndexerAnswer {
            tree: &empty,
            member: &identity(&member),
            sealed: None,
        }
        .openings();
        let client = zolana(RegistryRpc::of(empty), Lagging(AtomicU8::new(0), absent));
        assert!(!registered(ring(), &client, &member).expect("registered"));
        assert_eq!(client.indexer().0.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_changed_registry_root_is_refetched_before_retrying() {
        struct Advanced(
            AtomicU8,
            [u8; 32],
            zolana_client::GetRingMemberOpeningsResponse,
        );
        impl WitnessReader for Advanced {}
        impl Rpc for Advanced {
            fn get_ring_member_openings(
                &self,
                request: GetRingMemberOpeningsRequest,
            ) -> Result<zolana_client::GetRingMemberOpeningsResponse, ClientError> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    assert_eq!(request.expected_root.0, self.1);
                    return Err(ClientError::RingRegistryRootChanged);
                }
                assert_eq!(request.expected_root.0, self.2.root.root.0);
                Ok(self.2.clone())
            }
        }
        let member = member();
        let other = *Member::owner_tag(&[5; 32]).unwrap().as_bytes();
        let advanced = tree(&[QueueEntry {
            member: other,
            mask: 1,
            value: 1,
            escrow_key: [0; 32],
        }]);
        let answer = IndexerAnswer {
            tree: &advanced,
            member: &identity(&member),
            sealed: None,
        }
        .openings();
        let first = MemberRegistryTree::new().unwrap();
        let first_root = zolana_ring_member_registry::RecordTree::root(&first).unwrap();
        let rpc = RegistryRpc::of(first).advancing_to(advanced);
        let client = zolana(rpc, Advanced(AtomicU8::new(0), first_root, answer));
        assert!(!registered(ring(), &client, &member).expect("registered"));
        assert_eq!(client.indexer().0.load(Ordering::Relaxed), 2);
        assert_eq!(client.rpc().reads(), 2);
    }

    #[test]
    fn a_forged_record_cannot_skip_key_enrollment() {
        let member = member();
        let forged = |forge: fn(&mut RingMemberOpening)| {
            let mut served = Escrowed {
                member: &member,
                key_holder: &member,
            }
            .served();
            forge(&mut served.indexer.0.openings[0]);
            served.registered(&member)
        };
        assert!(matches!(
            ring_error(forged(|opening| opening.path.siblings[0][0].0[31] ^= 1)),
            RingError::Audit(AuditError::InvalidMemberRegistry)
        ));
        let sealed = forged(|opening| opening.record.ciphertext.as_mut().unwrap().0[31] ^= 1);
        assert!(!sealed.unwrap(), "a forged sealed key escrows nothing");
        assert!(matches!(
            ring_error(forged(|opening| opening.record.member.0[31] ^= 1)),
            RingError::Audit(AuditError::InvalidMemberRegistry)
        ));
    }

    #[test]
    fn another_escrowed_nullifier_key_does_not_enroll_the_sender() {
        let member = member();
        let mut different_key = ShieldedKeypair::new_ed25519().unwrap();
        different_key.signing_key = member.signing_key.clone();
        let served = Escrowed {
            member: &member,
            key_holder: &different_key,
        }
        .served();
        assert!(!served.registered(&member).unwrap());
    }

    #[test]
    fn a_transport_failure_is_not_read_as_unregistered() {
        struct Down;
        impl WitnessReader for Down {}
        impl Rpc for Down {
            fn get_ring_member_openings(
                &self,
                _request: GetRingMemberOpeningsRequest,
            ) -> Result<zolana_client::GetRingMemberOpeningsResponse, ClientError> {
                Err(ClientError::IndexerUnavailable("down".to_owned()))
            }
        }
        let empty = MemberRegistryTree::new().unwrap();
        assert!(matches!(
            ring_error(registered(
                ring(),
                &zolana(RegistryRpc::of(empty), Down),
                &member()
            )),
            RingError::Client(_)
        ));
    }
}
