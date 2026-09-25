use zk_program_sdk::{
    circuit,
    circuit::{
        Assert, Balance, CheckedTransaction, Circuit, ConfidentialTransaction, PublicInputs,
        TokenUtxo,
    },
    conversion::ProofInput,
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    shared::{keypair, token_input, MerklePath, MerkleTree},
};

#[derive(Clone, ProofInput)]
struct AllowlistedPayment {
    private: AllowlistedPaymentPrivateInputs,
    public: AllowlistedPaymentPublicInputs,
}

#[derive(Clone, ProofInput)]
struct AllowlistedPaymentPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
    amount: u64,
    path: MerklePath,
}

#[derive(Clone, ProofInput, PublicInputs)]
struct AllowlistedPaymentPublicInputs {
    root: [u8; 32],
    recipient: ShieldedAddress,
}

#[circuit]
impl Circuit for AllowlistedPayment {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        let public = &self.public;
        private
            .path
            .root(&public.recipient.hash()?)?
            .assert_equal(&public.root, "the recipient is not on the allowlist")?;
        let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
        let mut payment = TokenUtxo::new_init(&public.recipient, &tokens.asset());
        tokens.transfer(&mut payment, &private.amount)?;

        ConfidentialTransaction::new(&private.tx_context, public)
            .with_token_utxos(tokens)
            .with_token_utxos(payment)
            .check()
    }
}

#[test]
fn allowlisted_payment_prove_and_verify() {
    let sender = keypair(5);
    let address = sender.shielded_address().expect("sender address");
    let payer = address.solana_address().expect("payer");
    let recipient = keypair(6).shielded_address().expect("recipient address");
    let allowlist = MerkleTree::new(&[7u8, 6, 8].map(|seed| {
        keypair(seed)
            .shielded_address()
            .expect("allowlisted address")
            .owner_hash()
            .expect("allowlisted owner hash")
    }));
    let first = token_input(&sender, Mint::SOL, 300, 0);
    let second = token_input(&sender, Mint::SOL, 200, 1);

    let payment = AllowlistedPayment {
        private: AllowlistedPaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, second],
            amount: 400,
            path: allowlist.path(1),
        },
        public: AllowlistedPaymentPublicInputs {
            root: allowlist.root(),
            recipient,
        },
    };
    let spp_proof_inputs = payment
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .expect("allowlisted payment proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        vec![
            (Some(address), Mint::SOL, 100),
            (Some(recipient), Mint::SOL, 400),
        ]
    );

    let prover = Groth16Prover::<AllowlistedPayment>::new_with_test_setup()
        .expect("allowlisted payment setup");
    let result = prove(&prover, &payment, "allowlisted payment proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
