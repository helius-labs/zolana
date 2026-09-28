use zk_program_sdk::{
    circuit::{
        Balance, CheckedTransaction, Circuit, ConfidentialTransaction, Field, PublicInputs,
        TokenUtxo,
    },
    conversion::{field_bytes, ProofInput},
    testing::{check_private_variables, FreeVariable},
    CircuitError, Groth16Prover, TxContext, ZkProgram,
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::{ShieldedAddress, ShieldedKeypair};
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    gadgets::assert_isqrt,
    shared::{keypair, spendable, TREE_ID},
};

const ROOT_RULE: &str = "the public root is the integer square root of the private square";
const SWEPT: u64 = 500;

/// Sweeps the sender's tokens to a recipient and proves that the public root
/// is the integer square root of a private square.
#[derive(Clone, ProofInput)]
pub struct SquareRootSweep {
    private: SweepPrivateInputs,
    public: SquareRootSweepPublicInputs,
}

#[derive(Clone, ProofInput)]
struct SweepPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
    recipient: ShieldedAddress,
    square: u64,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct SquareRootSweepPublicInputs {
    root: u32,
}

#[deny(clippy::disallowed_types)]
impl Circuit for <SquareRootSweep as ProofInput>::Circuit {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        assert_isqrt(&private.square, &self.public.root, ROOT_RULE)?;
        let mut tokens = TokenUtxo::new_burn(&private.token_utxos_asset_a)?;
        let mut sweep = TokenUtxo::new_init(&private.recipient, &tokens.asset());
        tokens.transfer_all(&mut sweep)?;
        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_token_utxos(sweep)
            .check()
    }
}

fn private_inputs(
    sender: &ShieldedKeypair,
    recipient: ShieldedAddress,
    square: u64,
) -> SweepPrivateInputs {
    SweepPrivateInputs {
        tx_context: TxContext::new(),
        token_utxos_asset_a: [
            spendable(sender, Mint::SOL, SWEPT, 0),
            WalletUtxo::dummy(TREE_ID).expect("dummy"),
        ],
        recipient,
        square,
    }
}

#[test]
fn a_program_using_an_external_gadget_proves_and_verifies() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let sweep = SquareRootSweep {
        private: private_inputs(&sender, recipient, 17),
        public: SquareRootSweepPublicInputs { root: 4 },
    };
    let spp_proof_inputs = sweep
        .create_proof_inputs_and_encrypt_with_keys(&sender, payer, u64::MAX)
        .expect("sweep proof inputs");
    let private_tx_hash = spp_proof_inputs
        .padding_independent_private_tx_hash()
        .expect("private tx hash");
    let report = check_private_variables(&sweep).expect("private variable report");

    let prover = Groth16Prover::<SquareRootSweep>::new_with_test_setup().expect("sweep setup");
    let result = prover.prove(&sweep).expect("sweep proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");

    assert_eq!(
        (
            report.free,
            spp_proof_inputs
                .output_utxos
                .iter()
                .map(|output| (output.owner_address, output.asset, output.amount))
                .collect::<Vec<_>>(),
            result.public_hash,
        ),
        (
            Vec::<FreeVariable>::new(),
            vec![(Some(recipient), Mint::SOL, SWEPT)],
            Poseidon::hashv(&[
                field_bytes(&Field::from(4u64)).as_slice(),
                private_tx_hash.as_slice(),
            ])
            .expect("public hash"),
        )
    );
}

#[test]
fn a_wrong_public_root_breaks_the_program_rule() {
    let sender = keypair(5);
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let sweep = SquareRootSweep {
        private: private_inputs(&sender, recipient, 17),
        public: SquareRootSweepPublicInputs { root: 5 },
    };
    assert_eq!(
        sweep.check_constraints().map_err(|error| (
            error.name(),
            error.broken_rule(),
            error.location().file()
        )),
        Err(("CircuitError.RuleBroken", Some(ROOT_RULE), file!()))
    );
}
