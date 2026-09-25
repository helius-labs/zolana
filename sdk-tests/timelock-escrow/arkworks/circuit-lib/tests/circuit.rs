use circuit_lib::{
    constant,
    convert::{field_bytes, tx_context, utxo},
    poseidon,
    rand::{rngs::StdRng, SeedableRng},
    Allocator, ArkworksCircuit, Circuit, CircuitVar, ConfidentialTransaction, Field, ProofInput,
    PublicHash, PublicInputs, RelationError, TokenUtxo, TxContext, Utxo, U64,
};
use zolana_client::ProofInputUtxo;

const TREE_ID: u16 = 2;

fn bytes(value: u64) -> [u8; 32] {
    field_bytes(&Field::from(value))
}

#[derive(Clone, Debug)]
struct Payment {
    private: PaymentPrivateInputs,
    public: PaymentPublicInputs,
    public_hash: PublicHash,
}

#[derive(Clone, Debug)]
struct PaymentPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [Utxo; 2],
    amount: U64,
}

#[derive(Clone, Debug)]
struct PaymentPublicInputs {
    recipient: CircuitVar,
}

struct PaymentCircuit {
    private: PaymentPrivateInputsCircuit,
    public: PaymentPublicInputs,
    public_hash: CircuitVar,
}

struct PaymentPrivateInputsCircuit {
    tx_context: TxContext,
    token_utxos_asset_a: [Utxo; 2],
    amount: CircuitVar,
}

impl ProofInput for Payment {
    type Circuit = PaymentCircuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<PaymentCircuit, RelationError> {
        Ok(PaymentCircuit {
            private: PaymentPrivateInputsCircuit {
                tx_context: self.private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: self.private.token_utxos_asset_a.instantiate(allocator)?,
                amount: self.private.amount.instantiate(allocator)?,
            },
            public: PaymentPublicInputs {
                recipient: self.public.recipient.instantiate(allocator)?,
            },
            public_hash: self.public_hash.instantiate(allocator)?,
        })
    }
}

impl PublicInputs for PaymentPublicInputs {
    fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
        poseidon(&[self.recipient.clone(), private_tx_hash.clone()])
    }
}

impl Circuit for PaymentCircuit {
    fn circuit(&self) -> Result<CircuitVar, RelationError> {
        let private = &self.private;
        let mut tokens = TokenUtxo::new_mut(private.token_utxos_asset_a.clone())?;
        let payment = tokens.transfer(&self.public.recipient, private.amount.clone());
        ConfidentialTransaction::<_, 2, 2>::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_output_token_utxo(payment)
            .check()
    }

    fn public_hash(&self) -> &CircuitVar {
        &self.public_hash
    }
}

fn payment(amount: U64, public_hash: CircuitVar) -> Payment {
    let input = |amount: u64, blinding: u64| {
        utxo(
            &ProofInputUtxo::new(
                bytes(11),
                &[4u8; 32].into(),
                amount,
                &bytes(blinding),
                TREE_ID,
            )
            .unwrap(),
        )
        .unwrap()
    };
    Payment {
        private: PaymentPrivateInputs {
            tx_context: tx_context(&bytes(22), &bytes(23), TREE_ID).unwrap(),
            token_utxos_asset_a: [input(300, 1), input(200, 2)],
            amount,
        },
        public: PaymentPublicInputs {
            recipient: constant(30u64),
        },
        public_hash: PublicHash::new(public_hash),
    }
}

fn honest() -> Payment {
    let public_hash = payment(U64::from(400u64), constant(0u64))
        .instantiate(&Allocator::Native)
        .unwrap()
        .circuit()
        .unwrap();
    payment(U64::from(400u64), public_hash)
}

fn error<T>(result: Result<T, RelationError>) -> String {
    result.err().map(|e| e.to_string()).unwrap_or_default()
}

#[test]
fn a_circuit_runs_natively_and_in_r1cs_on_one_definition() {
    let honest = honest();
    let too_wide = payment(
        U64::new(constant(Field::from(u64::MAX) + Field::from(1u64))),
        constant(1u64),
    );
    let wrong_hash = payment(U64::from(400u64), constant(1u64));

    assert_eq!(
        (
            ArkworksCircuit::new(honest)
                .and_then(|circuit| circuit.check_constraints())
                .is_ok(),
            error(ArkworksCircuit::new(too_wide.clone())),
            error(ArkworksCircuit::new(wrong_hash.clone())),
            ArkworksCircuit::unchecked(too_wide)
                .and_then(|circuit| circuit.check_constraints())
                .is_err(),
            ArkworksCircuit::unchecked(wrong_hash)
                .and_then(|circuit| circuit.check_constraints())
                .is_err(),
        ),
        (
            true,
            "a value does not fit in 64 bits".to_string(),
            "the public hash does not match".to_string(),
            true,
            true,
        )
    );
}

#[test]
fn a_groth16_proof_verifies_and_compresses() {
    let circuit = ArkworksCircuit::new(honest()).unwrap();
    let mut rng = StdRng::seed_from_u64(7);
    let keys = circuit.setup(&mut rng).unwrap();
    let proof = circuit.prove(&keys, &mut rng).unwrap();
    let mut tampered = circuit.public_hash_bytes();
    tampered[31] ^= 1;

    assert_eq!(
        (
            proof
                .verify(keys.verifying_key(), circuit.public_hash_bytes())
                .is_ok(),
            error(proof.verify(keys.verifying_key(), tampered)),
            proof.compress().is_ok(),
            keys.verifying_key().ic.len(),
        ),
        (
            true,
            "the proof does not verify under these keys".to_string(),
            true,
            2
        )
    );
}
