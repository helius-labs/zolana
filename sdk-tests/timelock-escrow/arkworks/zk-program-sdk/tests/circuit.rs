use ark_relations::r1cs::SynthesisError;
use borsh::{BorshDeserialize, BorshSerialize};
use groth16_solana::{groth16::Groth16Verifier, vk::gnark::parse_gnark_vk_bytes};
use solana_address::Address;
use zk_program_sdk::{
    circuit::{value, Circuit, ConstraintSystem, Field},
    conversion::{to_bytes, Allocator, FromCircuit, ProofInput},
    rand::{rngs::StdRng, SeedableRng},
    ArkworksCircuit, CompressedProof, Groth16Keys, RelationError, TxContext, VerifyingKeyExport,
    ZkProgram,
};
use zolana_interface::instruction::instruction_data::transact::OwnerTag;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{
    instructions::transact::SppProofInputs, utxo::SppProofInputUtxo, Mint, WalletUtxo,
};

mod shared;
use shared::{keypair, spendable, TREE_ID};

#[derive(Clone)]
struct Payment {
    private: PaymentPrivateInputs,
    public: RecipientPublicInputs,
}

#[derive(Clone)]
struct PaymentPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
    amount: u64,
}

#[derive(Clone)]
struct RecipientPublicInputs {
    recipient: ShieldedAddress,
}

impl ProofInput for RecipientPublicInputs {
    type Circuit = circuit::RecipientPublicInputs;

    fn instantiate(
        &self,
        allocator: &Allocator,
    ) -> Result<circuit::RecipientPublicInputs, RelationError> {
        Ok(circuit::RecipientPublicInputs {
            recipient: self.recipient.instantiate(allocator)?,
        })
    }
}

impl ProofInput for Payment {
    type Circuit = circuit::Payment;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Payment, RelationError> {
        let private = &self.private;
        Ok(circuit::Payment {
            private: circuit::PaymentPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                amount: private.amount.instantiate(allocator)?,
            },
            public: self.public.instantiate(allocator)?,
        })
    }
}

impl ZkProgram for Payment {}

#[derive(Clone)]
struct Sweep {
    private: SweepPrivateInputs,
    public: RecipientPublicInputs,
}

#[derive(Clone)]
struct SweepPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 2],
    amount: u64,
}

impl ProofInput for Sweep {
    type Circuit = circuit::Sweep;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Sweep, RelationError> {
        let private = &self.private;
        Ok(circuit::Sweep {
            private: circuit::SweepPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                amount: private.amount.instantiate(allocator)?,
            },
            public: self.public.instantiate(allocator)?,
        })
    }
}

impl ZkProgram for Sweep {}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Label {
    value: u64,
}

impl ProofInput for Label {
    type Circuit = circuit::Label;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Label, RelationError> {
        Ok(circuit::Label {
            value: self.value.instantiate(allocator)?,
        })
    }
}

impl FromCircuit for Label {
    fn from_circuit(circuit: &circuit::Label) -> Result<Self, RelationError> {
        Ok(Self {
            value: u64::from_circuit(&circuit.value)?,
        })
    }
}

#[derive(Clone)]
struct Register {
    private: RegisterPrivateInputs,
    public: RegisterPublicInputs,
}

#[derive(Clone)]
struct RegisterPrivateInputs {
    tx_context: TxContext,
    token_utxos_asset_a: [WalletUtxo; 1],
    owner: ShieldedAddress,
}

#[derive(Clone)]
struct RegisterPublicInputs {
    label: u64,
}

impl ProofInput for Register {
    type Circuit = circuit::Register;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Register, RelationError> {
        let private = &self.private;
        Ok(circuit::Register {
            private: circuit::RegisterPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                token_utxos_asset_a: private.token_utxos_asset_a.instantiate(allocator)?,
                owner: private.owner.instantiate(allocator)?,
            },
            public: circuit::RegisterPublicInputs {
                label: self.public.label.instantiate(allocator)?,
            },
        })
    }
}

impl ZkProgram for Register {}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
            DataHash, DataUtxo, Owner, PublicInputs, TokenUtxo, TxContext, Utxo, UtxoData,
        },
        RelationError,
    };

    pub struct Payment {
        pub private: PaymentPrivateInputs,
        pub public: RecipientPublicInputs,
    }

    pub struct PaymentPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 2],
        pub amount: CircuitVar,
    }

    pub struct RecipientPublicInputs {
        pub recipient: Owner,
    }

    impl PublicInputs for RecipientPublicInputs {
        fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.recipient.hash()?, private_tx_hash.clone()])
        }
    }

    impl Circuit for Payment {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let mut tokens = TokenUtxo::new_mut(private.token_utxos_asset_a.clone())?;
            let payment = tokens.transfer(&self.public.recipient, private.amount.clone());
            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_output_token_utxo(payment)
                .check()
        }
    }

    pub struct Sweep {
        pub private: SweepPrivateInputs,
        pub public: RecipientPublicInputs,
    }

    pub struct SweepPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 2],
        pub amount: CircuitVar,
    }

    impl Circuit for Sweep {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let mut tokens = TokenUtxo::new_burn(private.token_utxos_asset_a.clone())?;
            let payment = tokens.transfer(&self.public.recipient, private.amount.clone());
            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_output_token_utxo(payment)
                .check()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Label {
        pub value: CircuitVar,
    }

    impl Default for Label {
        fn default() -> Self {
            Self { value: zero() }
        }
    }

    impl DataHash for Label {
        fn hash(&self) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.value.hash()?])
        }
    }

    impl UtxoData for Label {
        type Client = super::Label;
    }

    pub struct Register {
        pub private: RegisterPrivateInputs,
        pub public: RegisterPublicInputs,
    }

    pub struct RegisterPrivateInputs {
        pub tx_context: TxContext,
        pub token_utxos_asset_a: [Utxo; 1],
        pub owner: Owner,
    }

    pub struct RegisterPublicInputs {
        pub label: CircuitVar,
    }

    impl PublicInputs for RegisterPublicInputs {
        fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.label.clone(), private_tx_hash.clone()])
        }
    }

    impl Circuit for Register {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let tokens = TokenUtxo::new_mut(private.token_utxos_asset_a.clone())?;
            let mut label = DataUtxo::<Label>::new_init(&private.owner)?;
            label.value = self.public.label.clone();
            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_data_utxo(label)
                .check()
        }
    }
}

fn r1cs_refuses<P>(proof_inputs: P) -> bool
where
    P: ProofInput + Clone,
    P::Circuit: Circuit,
{
    let cs = ConstraintSystem::new_ref();
    match proof_inputs
        .instantiate(&Allocator::R1cs(cs))
        .and_then(|circuit| circuit.circuit())
    {
        Err(RelationError::Synthesis(
            SynthesisError::AssignmentMissing | SynthesisError::DivisionByZero,
        )) => true,
        Err(error) => panic!("unexpected R1CS error: {error}"),
        Ok(checked) => ArkworksCircuit::with_public_hash(
            proof_inputs,
            value(checked.public_hash()).expect("own public hash"),
        )
        .check_constraints()
        .is_err(),
    }
}

fn encrypt<P: ZkProgram>(proof_inputs: P) -> Result<SppProofInputs, String> {
    proof_inputs
        .create_proof_inputs_and_encrypt(&keypair(5), Address::new_unique(), u64::MAX)
        .map(|(_, spp_proof_inputs)| spp_proof_inputs)
        .map_err(|e| e.to_string())
}

#[test]
fn a_circuit_runs_natively_and_in_r1cs_on_one_definition() {
    let sender = keypair(5);
    let first = spendable(&sender, Mint::SOL, 300, 0);
    let honest = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(
                first.nullifier,
                TREE_ID,
                keypair(5).shielded_address().unwrap(),
            ),
            token_utxos_asset_a: [first, spendable(&sender, Mint::SOL, 200, 1)],
            amount: 400,
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    };
    let mut other_owner = honest.clone();
    if let Some(second) = other_owner.private.token_utxos_asset_a.get_mut(1) {
        *second = spendable(&keypair(7), Mint::SOL, 200, 1);
    }
    let circuit = ArkworksCircuit::new(honest.clone()).unwrap();

    assert_eq!(
        (
            circuit.check_constraints().is_ok(),
            r1cs_refuses(honest.clone()),
            ArkworksCircuit::with_public_hash(honest, Field::from(1u64))
                .check_constraints()
                .is_err(),
            ArkworksCircuit::new(other_owner.clone())
                .err()
                .map(|e| e.to_string()),
            r1cs_refuses(other_owner),
        ),
        (
            true,
            false,
            true,
            Some("the inputs belong to different owners".to_string()),
            true,
        )
    );
}

#[test]
fn a_groth16_proof_verifies_and_compresses() {
    let sender = keypair(5);
    let first = spendable(&sender, Mint::SOL, 300, 0);
    let circuit = ArkworksCircuit::new(Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(
                first.nullifier,
                TREE_ID,
                keypair(5).shielded_address().unwrap(),
            ),
            token_utxos_asset_a: [first, spendable(&sender, Mint::SOL, 200, 1)],
            amount: 400,
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    })
    .unwrap();
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
            proof
                .verify(keys.verifying_key(), tampered)
                .err()
                .map(|e| e.to_string()),
            CompressedProof::try_from(&proof).is_ok(),
            keys.verifying_key().ic.len(),
        ),
        (
            true,
            Some("the proof does not verify under these keys".to_string()),
            true,
            2
        )
    );
}

#[test]
fn the_native_run_produces_the_spp_transaction() {
    let sender = keypair(5);
    let sender_address = sender.shielded_address().unwrap();
    let recipient = keypair(6).shielded_address().unwrap();
    let first = spendable(&sender, Mint::SOL, 300, 0);
    let second = spendable(&sender, Mint::SOL, 200, 1);
    let input_hashes = vec![first.utxo_hash, second.utxo_hash];
    let payment = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(
                first.nullifier,
                TREE_ID,
                keypair(5).shielded_address().unwrap(),
            ),
            token_utxos_asset_a: [first, second],
            amount: 400,
        },
        public: RecipientPublicInputs { recipient },
    };
    let native = payment
        .instantiate(&Allocator::native())
        .unwrap()
        .circuit()
        .unwrap();
    let (returned, spp) = payment
        .create_proof_inputs_and_encrypt(&sender, sender_address.solana_address().unwrap(), 9)
        .unwrap();

    assert_eq!(
        (
            spp.input_utxos
                .iter()
                .map(|input| input.utxo_hash)
                .collect::<Vec<_>>(),
            spp.output_utxos
                .iter()
                .map(|output| (output.owner_address, output.amount))
                .collect::<Vec<_>>(),
            spp.external_data
                .outputs
                .iter()
                .map(|output| output.owner_tag)
                .collect::<Vec<_>>(),
            spp.external_data.expiry_unix_ts,
            spp.padding_independent_private_tx_hash().unwrap(),
            ArkworksCircuit::new(returned).unwrap().public_hash_bytes(),
        ),
        (
            input_hashes,
            vec![(Some(sender_address), 100), (Some(recipient), 400)],
            vec![
                OwnerTag::Account(0),
                OwnerTag::Inline(recipient.signing_pubkey.confidential_view_tag().unwrap()),
            ],
            9,
            to_bytes(native.private_tx_hash()).unwrap(),
            to_bytes(native.public_hash()).unwrap(),
        )
    );
}

#[test]
fn logic_dummies_are_dropped_and_unused_outputs_are_empty_utxos() {
    let first = spendable(&keypair(5), Mint::SOL, 500, 0);
    let recipient = keypair(6).shielded_address().unwrap();
    let sweep = |token_utxos_asset_a, amount| {
        let spp = encrypt(Sweep {
            private: SweepPrivateInputs {
                tx_context: TxContext::new(
                    first.nullifier,
                    TREE_ID,
                    keypair(5).shielded_address().unwrap(),
                ),
                token_utxos_asset_a,
                amount,
            },
            public: RecipientPublicInputs { recipient },
        })
        .unwrap();
        (
            spp.input_utxos
                .iter()
                .map(SppProofInputUtxo::is_dummy)
                .collect::<Vec<_>>(),
            spp.output_utxos
                .iter()
                .map(|output| (output.owner_address, output.amount))
                .collect::<Vec<_>>(),
            spp.external_data
                .outputs
                .iter()
                .map(|output| output.data.is_some())
                .collect::<Vec<_>>(),
        )
    };

    assert_eq!(
        (
            sweep([first.clone(), WalletUtxo::dummy(TREE_ID).unwrap()], 500),
            sweep(
                [first.clone(), spendable(&keypair(5), Mint::SOL, 200, 1)],
                700
            ),
        ),
        (
            (vec![false], vec![(Some(recipient), 500)], vec![true]),
            (
                vec![false, false],
                vec![(Some(recipient), 700), (None, 0)],
                vec![true, true],
            ),
        )
    );
}

#[test]
fn a_valueless_data_utxo_is_sol_without_a_sol_input() {
    let owner = keypair(5);
    let mint = Mint::new(Address::new_from_array([9u8; 32]), 9);
    let first = spendable(&owner, mint, 150, 0);
    let register = Register {
        private: RegisterPrivateInputs {
            tx_context: TxContext::new(
                first.nullifier,
                TREE_ID,
                keypair(5).shielded_address().unwrap(),
            ),
            token_utxos_asset_a: [first],
            owner: owner.shielded_address().unwrap(),
        },
        public: RegisterPublicInputs { label: 42 },
    };
    let circuit = ArkworksCircuit::new(register.clone()).unwrap();
    let spp = encrypt(register).unwrap();
    let label_data = spp
        .output_utxos
        .get(1)
        .and_then(|output| output.data.utxo_data())
        .map(<[u8]>::to_vec)
        .unwrap_or_default();

    assert_eq!(
        (
            spp.output_utxos
                .iter()
                .map(|output| (output.asset, output.amount, output.data_hash.is_some()))
                .collect::<Vec<_>>(),
            label_data.clone(),
            Label::try_from_slice(&label_data).ok(),
            circuit.check_constraints().is_ok(),
        ),
        (
            vec![(mint, 150, false), (Mint::SOL, 0, true)],
            borsh::to_vec(&Label { value: 42 }).unwrap(),
            Some(Label { value: 42 }),
            true,
        )
    );
}

#[test]
fn every_resolution_failure_is_named() {
    let sender = keypair(5);
    let first = spendable(&sender, Mint::SOL, 300, 0);
    let honest = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(
                first.nullifier,
                TREE_ID,
                keypair(5).shielded_address().unwrap(),
            ),
            token_utxos_asset_a: [first, spendable(&sender, Mint::SOL, 200, 1)],
            amount: 400,
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    };
    let mut other_nullifier = honest.clone();
    other_nullifier.private.tx_context =
        TxContext::new([7u8; 32], TREE_ID, keypair(5).shielded_address().unwrap());
    let stranger = keypair(7);
    let mut unnamed_change_owner = honest.clone();
    unnamed_change_owner.private.tx_context.sender = stranger.shielded_address().unwrap();
    let mut overspend = honest;
    overspend.private.amount = 600;

    assert_eq!(
        (
            encrypt(other_nullifier).err(),
            unnamed_change_owner
                .create_proof_inputs_and_encrypt(&stranger, Address::new_unique(), u64::MAX)
                .err()
                .map(|e| e.to_string()),
            encrypt(overspend).err(),
        ),
        (
            Some("the first nullifier is not the first input's".to_string()),
            Some("output slot 0 has an owner no input names".to_string()),
            Some("output slot 0 has an amount that does not fit in u64".to_string()),
        )
    );
}

#[test]
fn setup_saves_loads_and_exports_the_keys() {
    let sender = keypair(5);
    let first = spendable(&sender, Mint::SOL, 300, 0);
    let circuit = ArkworksCircuit::new(Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(
                first.nullifier,
                TREE_ID,
                keypair(5).shielded_address().unwrap(),
            ),
            token_utxos_asset_a: [first, spendable(&sender, Mint::SOL, 200, 1)],
            amount: 400,
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    })
    .unwrap();
    let mut rng = StdRng::seed_from_u64(7);
    let keys = circuit.setup(&mut rng).unwrap();
    let dir = std::env::temp_dir().join(format!("zk-program-sdk-keys-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let proving_key = dir.join("pk.bin");
    keys.save(&proving_key).unwrap();
    let loaded = Groth16Keys::load(&proving_key).unwrap();
    let proof = circuit.prove(&loaded, &mut rng).unwrap();
    let parsed = parse_gnark_vk_bytes(&keys.gnark_verifying_key().unwrap()).unwrap();
    let parsed_accepts = {
        let public_inputs = [circuit.public_hash_bytes()];
        let verifying_key = parsed.as_borrowed();
        Groth16Verifier::new(&proof.a, &proof.b, &proof.c, &public_inputs, &verifying_key)
            .and_then(|mut verifier| verifier.verify())
            .is_ok()
    };
    keys.export_verifying_key(&VerifyingKeyExport {
        proving_key: &proving_key,
        output_dir: &dir,
        output_filename: "payment.rs",
        const_name: "VERIFYINGKEY",
    })
    .unwrap();
    let exported = std::fs::read_to_string(dir.join("payment.rs")).unwrap();
    let leftovers = std::fs::read_dir(&dir).unwrap().count();
    std::fs::remove_dir_all(&dir).unwrap();

    assert_eq!(
        (
            loaded.verifying_key() == keys.verifying_key(),
            proof
                .verify(keys.verifying_key(), circuit.public_hash_bytes())
                .is_ok(),
            (
                parsed.vk_alpha_g1,
                parsed.vk_delta_g2,
                parsed.vk_ic.clone(),
                parsed.nr_pubinputs
            ),
            parsed_accepts,
            exported.contains("pub const VERIFYINGKEY: Groth16Verifyingkey"),
            exported.contains("pub const VERIFYINGKEY_INSECURE_TEST_SETUP: bool = true;"),
            exported.contains("VERIFYINGKEY_PROVING_KEY_SHA256"),
            leftovers,
        ),
        (
            true,
            true,
            (
                keys.verifying_key().alpha_g1,
                keys.verifying_key().delta_g2,
                keys.verifying_key().ic.clone(),
                1
            ),
            true,
            true,
            true,
            true,
            2,
        )
    );
}
