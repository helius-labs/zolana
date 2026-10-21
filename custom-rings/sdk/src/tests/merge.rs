use custom_ring_interface::{CoSignScope, RingMode};
use solana_signer::Signer;
use zolana_interface::pda;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::Mint;

use super::support::{keypair, ring, ring_note, Chain, RingSettings, TREE_ID};
use crate::{
    CustomRingMerge, MergeProofInput, PreparedCustomRingMerge, RingError, RingMergeOperation,
    RingSubmission,
};

struct Merge<'a> {
    owner: &'a ShieldedKeypair,
    settings: RingSettings,
    payer: &'a ShieldedKeypair,
}

fn prepared(owner: &ShieldedKeypair) -> PreparedCustomRingMerge {
    let notes = (0..2)
        .map(|leaf| ring_note(owner, Mint::SOL, 5, leaf))
        .collect();
    CustomRingMerge::new(ring(), notes, None)
        .unwrap()
        .encrypt(owner)
        .unwrap()
}

impl Merge<'_> {
    async fn refusal(self) -> RingError {
        let merge = RingMergeOperation::new(
            prepared(self.owner),
            MergeProofInput {
                nullifier_key: self.owner.nullifier_key.clone(),
                input_tree: pda::tree(TREE_ID),
                output_tree: pda::tree(TREE_ID),
            },
        );
        RingSubmission::new(merge)
            .send(&Chain::ring(self.settings).client(), self.payer, &[])
            .await
            .unwrap_err()
    }
}

/// The hidden owner never pays or co-signs its anonymous merge.
#[tokio::test]
async fn an_anonymous_merge_its_owner_would_sign_in_public_is_refused_before_proving() {
    let owner = keypair(1);
    let anonymous = RingSettings::new(RingMode::Anonymous);
    let refusal = |settings, payer| {
        Merge {
            owner: &owner,
            settings,
            payer,
        }
        .refusal()
    };
    assert!(matches!(
        refusal(anonymous, &owner).await,
        RingError::AnonymousPublicSignerLinksOwner
    ));
    let co_signed = RingSettings {
        co_signer: Some((owner.pubkey(), CoSignScope::TRANSFERS)),
        ..anonymous
    };
    let payer = keypair(9);
    assert!(matches!(
        refusal(co_signed, &payer).await,
        RingError::AnonymousPublicSignerLinksOwner
    ));
    let confidential = ring()
        .require_config(&Chain::ring(RingSettings::new(RingMode::Off)))
        .await
        .unwrap();
    assert!(prepared(&owner)
        .check_public_signers(owner.pubkey(), &confidential)
        .is_ok());
}
