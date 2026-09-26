use borsh::{BorshDeserialize, BorshSerialize};
use zk_program_sdk::{
    circuit,
    circuit::{
        constant, Asset, Bits, CheckedTransaction, Circuit, CircuitType, ConfidentialTransaction,
        DataUtxo, PublicInputs,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{data_input, keypair},
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct Profile {
    pub score: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, CircuitType)]
pub struct Badge {
    pub level: u16,
}

#[derive(Clone, ProofInput)]
struct CreateAndUpdate {
    private: CreateAndUpdatePrivateInputs,
    public: CreateAndUpdatePublicInputs,
}

#[derive(Clone, ProofInput)]
struct CreateAndUpdatePrivateInputs {
    tx_context: TxContext,
    profile_utxo: WalletUtxo,
    profile: Profile,
    level: u16,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct CreateAndUpdatePublicInputs {
    badge_owner: ShieldedAddress,
}

#[circuit]
impl Circuit for CreateAndUpdate {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut profile = DataUtxo::new_mut(&private.profile_utxo, &private.profile)?;
        profile.score = profile.score.clone() + constant(1u64);
        profile.score.check_bits(64)?;
        let mut badge = DataUtxo::<BadgeCircuit>::new_init(&self.public.badge_owner, &Asset::sol());
        badge.level = private.level.clone();

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_data_utxo(profile)
            .with_data_utxo(badge)
            .check()
    }
}

#[test]
fn create_and_update_prove_and_verify() {
    let owner = keypair(5);
    let address = owner.shielded_address().expect("owner address");
    let payer = address.solana_address().expect("payer");
    let badge_owner = keypair(6).shielded_address().expect("badge owner address");
    let profile = Profile { score: 41 };
    let profile_utxo = data_input(&owner, 0, &profile, 0);

    let create_and_update = CreateAndUpdate {
        private: CreateAndUpdatePrivateInputs {
            tx_context: TxContext::new(),
            profile_utxo,
            profile,
            level: 2,
        },
        public: CreateAndUpdatePublicInputs { badge_owner },
    };
    let spp_proof_inputs = create_and_update
        .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
        .expect("create and update proof inputs");
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
                Some(borsh::to_vec(&Profile { score: 42 }).expect("profile bytes")),
            ),
            (
                Some(badge_owner),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&Badge { level: 2 }).expect("badge bytes")),
            ),
        ]
    );

    let prover =
        Groth16Prover::<CreateAndUpdate>::new_with_test_setup().expect("create and update setup");
    let result = prove(&prover, &create_and_update, "create and update proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
