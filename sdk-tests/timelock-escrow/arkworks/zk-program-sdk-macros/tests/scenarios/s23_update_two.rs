use zk_program_sdk::{
    circuit,
    circuit::{
        constant, Assert, Balance, Bits, CheckedTransaction, Circuit, ConfidentialTransaction,
        DataUtxo, PublicInputs,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s22_create_and_update::{Badge, Profile},
    shared::{data_input, keypair},
};

#[derive(Clone, ProofInput)]
struct UpdateTwo {
    private: UpdateTwoPrivateInputs,
    public: UpdateTwoPublicInputs,
}

#[derive(Clone, ProofInput)]
struct UpdateTwoPrivateInputs {
    tx_context: TxContext,
    profile_utxo: WalletUtxo,
    profile: Profile,
    badge_utxo: WalletUtxo,
    badge: Badge,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct UpdateTwoPublicInputs {
    owner: ShieldedAddress,
}

#[circuit]
impl Circuit for UpdateTwo {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let owner = self.public.owner.hash()?;
        let mut profile = DataUtxo::new_mut(&private.profile_utxo, &private.profile)?;
        profile
            .owner()
            .hash()?
            .assert_equal(&owner, "the profile has another owner")?;
        profile.score = profile.score.clone() + constant(10u64);
        profile.score.check_bits(64)?;
        let mut badge = DataUtxo::new_mut(&private.badge_utxo, &private.badge)?;
        badge
            .owner()
            .hash()?
            .assert_equal(&owner, "the badge has another owner")?;
        badge.level = badge.level.clone() + constant(1u64);
        badge.level.check_bits(16)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_data_utxo(profile)
            .with_data_utxo(badge)
            .check()
    }
}

#[test]
fn update_two_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let profile = Profile { score: 41 };
    let badge = Badge { level: 2 };
    let profile_utxo = data_input(&owner, 0, &profile, 0);
    let badge_utxo = data_input(&owner, 0, &badge, 1);

    let update_two = UpdateTwo {
        private: UpdateTwoPrivateInputs {
            tx_context: TxContext::new(),
            profile_utxo,
            profile,
            badge_utxo,
            badge,
        },
        public: UpdateTwoPublicInputs { owner: address },
    };
    let spp_proof_inputs = update_two
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("update two proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (
                output.owner_address,
                output.asset,
                output.amount,
                output.data.utxo_data().map(<[u8]>::to_vec),
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                Some(address),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&Profile { score: 51 }).expect("profile bytes")),
            ),
            (
                Some(address),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&Badge { level: 3 }).expect("badge bytes")),
            ),
        ]
    );

    let prover = Groth16Prover::<UpdateTwo>::new_with_test_setup().expect("update two setup");
    let result = prove(&prover, &update_two, "update two proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
