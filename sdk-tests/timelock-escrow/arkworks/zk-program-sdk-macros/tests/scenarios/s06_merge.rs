use zk_program_sdk::{
    circuit,
    circuit::{
        Assert, Balance, CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs,
        TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_interface::shape::Shape;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, on_large_stack, token_input},
};

const MERGED_INPUTS: usize = 36;

#[derive(Clone, ProofInput)]
struct Merge {
    private: MergePrivateInputs,
    public: MergePublicInputs,
}

#[derive(Clone, ProofInput)]
struct MergePrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; MERGED_INPUTS],
}

#[derive(Clone, ProofInput, PublicInputs)]
struct MergePublicInputs {
    owner: ShieldedAddress,
}

#[circuit]
impl Circuit for Merge {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let mut tokens = TokenUtxo::new_burn(&private.token_utxos_asset_a)?;
        tokens
            .owner()
            .hash()?
            .assert_equal(&self.public.owner.hash()?, "the inputs have another owner")?;
        let mut merged = TokenUtxo::new_init(&self.public.owner, &tokens.asset());
        tokens.transfer_all(&mut merged)?;

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_token_utxos(merged)
            .check()
    }
}

#[test]
fn merge_prove_and_verify() {
    on_large_stack(|| {
        let owner = keypair(5);
        let address = owner.shielded_address().expect("owner address");
        let payer = address.solana_address().expect("payer");
        let inputs: [WalletUtxo; MERGED_INPUTS] = std::array::from_fn(|index| {
            let leaf_index = u64::try_from(index).expect("leaf index");
            token_input(&owner, Mint::SOL, 10 + leaf_index, leaf_index)
        });
        let total: u64 = inputs.iter().map(|input| input.utxo.amount).sum();

        let merge = Merge {
            private: MergePrivateInputs {
                tx_context: TxContext::new(),
                token_utxos_asset_a: inputs,
            },
            public: MergePublicInputs { owner: address },
        };
        let spp_proof_inputs = merge
            .create_proof_inputs_and_encrypt(&owner, payer, u64::MAX)
            .expect("merge proof inputs");
        assert_eq!(
            (
                spp_proof_inputs.check_shape().expect("merge shape"),
                spp_proof_inputs
                    .output_utxos
                    .iter()
                    .map(|output| (output.owner_address, output.asset, output.amount))
                    .collect::<Vec<_>>(),
            ),
            (
                Shape::IN36_OUT2,
                vec![(Some(address), Mint::SOL, total), (None, Mint::SOL, 0),]
            )
        );

        let prover = Groth16Prover::<Merge>::new_with_test_setup().expect("merge setup");
        let result = prove(&prover, &merge, "merge proof");
        prover
            .verify(&result)
            .expect("the compressed proof verifies");
    });
}
