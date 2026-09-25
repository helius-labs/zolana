use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
use ark_relations::r1cs::SynthesisError;
use borsh::{BorshDeserialize, BorshSerialize};
use groth16_solana::{groth16::Groth16Verifier, vk::gnark::parse_gnark_vk_bytes};
use solana_address::Address;
use zk_program_sdk::{
    circuit::{constant, Circuit, CircuitVar, ConstraintSystem, Field},
    conversion::{to_bytes, Allocator, FromCircuit, Placeholder, ProofInput},
    Groth16Keys, Groth16Prover, RelationError, TxContext, VerifyingKeyExport, ZkProgram,
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

impl zk_program_sdk::circuit::CircuitType for circuit::RecipientPublicInputs {}

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

impl zk_program_sdk::circuit::CircuitType for circuit::Payment {}

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

impl Placeholder for Payment {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: PaymentPrivateInputs {
                tx_context: TxContext::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                amount: 0,
            },
            public: RecipientPublicInputs {
                recipient: ShieldedAddress::placeholder()?,
            },
        })
    }
}

#[derive(Clone)]
struct DivergingPayment {
    payment: Payment,
}

impl ProofInput for DivergingPayment {
    type Circuit = circuit::Payment;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Payment, RelationError> {
        let mut payment = self.payment.clone();
        if let Allocator::R1cs(_) = allocator {
            payment.private.amount += 1;
        }
        payment.instantiate(allocator)
    }
}

impl Placeholder for DivergingPayment {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            payment: Payment::placeholder()?,
        })
    }
}

#[derive(Clone)]
struct ReshapedPayment {
    payment: Payment,
    extra_input: bool,
}

impl ProofInput for ReshapedPayment {
    type Circuit = circuit::Payment;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Payment, RelationError> {
        if self.extra_input {
            let _extra = allocator.private_input(&constant(0u64))?;
        }
        self.payment.instantiate(allocator)
    }
}

impl Placeholder for ReshapedPayment {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            payment: Payment::placeholder()?,
            extra_input: false,
        })
    }
}

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

impl zk_program_sdk::circuit::CircuitType for circuit::Sweep {}

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

impl Placeholder for Sweep {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: SweepPrivateInputs {
                tx_context: TxContext::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                amount: 0,
            },
            public: RecipientPublicInputs {
                recipient: ShieldedAddress::placeholder()?,
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Label {
    value: u64,
}

impl zk_program_sdk::circuit::CircuitType for circuit::Label {}

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

impl zk_program_sdk::circuit::CircuitType for circuit::Register {}

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

impl Placeholder for Register {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: RegisterPrivateInputs {
                tx_context: TxContext::placeholder()?,
                token_utxos_asset_a: Placeholder::placeholder()?,
                owner: ShieldedAddress::placeholder()?,
            },
            public: RegisterPublicInputs { label: 0 },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, zero, Asset, Balance, CheckedTransaction, Circuit, CircuitMarker, CircuitVar,
            ConfidentialTransaction, DataHash, DataUtxo, Owner, PublicInputs, TokenUtxo, TxContext,
            Utxo, UtxoData,
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
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let mut tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let mut payment = TokenUtxo::new_init(&self.public.recipient, &tokens.asset());
            tokens.transfer(&mut payment, &private.amount)?;
            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_token_utxos(payment)
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
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let mut tokens = TokenUtxo::new_burn(&private.token_utxos_asset_a)?;
            let mut payment = TokenUtxo::new_init(&self.public.recipient, &tokens.asset());
            tokens.transfer(&mut payment, &private.amount)?;
            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_token_utxos(payment)
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
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let tokens = TokenUtxo::new_mut(&private.token_utxos_asset_a)?;
            let mut label = DataUtxo::<Label>::new_init(&private.owner, &Asset::sol());
            label.value = self.public.label.clone();
            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_token_utxos(tokens)
                .with_data_utxo(label)
                .check()
        }
    }
}

fn r1cs_refuses<P>(proof_inputs: &P) -> bool
where
    P: ProofInput,
    P::Circuit: Circuit,
{
    let cs = ConstraintSystem::new_ref();
    match proof_inputs
        .instantiate(&Allocator::R1cs(cs.clone()))
        .and_then(|circuit| circuit.circuit())
    {
        Err(RelationError::Synthesis(
            SynthesisError::AssignmentMissing | SynthesisError::DivisionByZero,
        )) => true,
        Err(error) => panic!("unexpected R1CS error: {error}"),
        Ok(_) => !cs.is_satisfied().expect("satisfiability"),
    }
}

fn satisfied_with_public_hash<P>(proof_inputs: &P, public_hash: Field) -> bool
where
    P: ProofInput,
    P::Circuit: Circuit,
{
    let cs = ConstraintSystem::new_ref();
    let public_input =
        CircuitVar::new_input(cs.clone(), || Ok(public_hash)).expect("public hash input");
    proof_inputs
        .instantiate(&Allocator::R1cs(cs.clone()))
        .and_then(|circuit| circuit.circuit())
        .expect("r1cs circuit")
        .public_hash()
        .enforce_equal(&public_input)
        .expect("public hash constraint");
    cs.is_satisfied().expect("satisfiability")
}

fn encrypt<P: ZkProgram>(proof_inputs: &P) -> Result<SppProofInputs, String> {
    proof_inputs
        .create_proof_inputs_and_encrypt(&keypair(5), Address::new_unique(), u64::MAX)
        .map_err(|e| e.to_string())
}

#[test]
fn a_circuit_runs_natively_and_in_r1cs_on_one_definition() {
    let sender = keypair(5);
    let first = spendable(&sender, Mint::SOL, 300, 0);
    let honest = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(),
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

    assert_eq!(
        (
            honest.check_constraints().is_ok(),
            r1cs_refuses(&honest),
            satisfied_with_public_hash(&honest, Field::from(1u64)),
            other_owner.check_constraints().err().map(|e| e.to_string()),
            r1cs_refuses(&other_owner),
        ),
        (
            true,
            false,
            false,
            Some("the inputs belong to different owners".to_string()),
            true,
        )
    );
}

#[test]
fn a_groth16_proof_verifies_in_its_compressed_form() {
    let sender = keypair(5);
    let first = spendable(&sender, Mint::SOL, 300, 0);
    let payment = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, spendable(&sender, Mint::SOL, 200, 1)],
            amount: 400,
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    };
    let native = payment
        .instantiate(&Allocator::native())
        .unwrap()
        .circuit()
        .unwrap();
    let prover = Groth16Prover::<Payment>::new_with_test_setup().unwrap();
    let result = prover.prove(&payment).unwrap();
    let mut tampered = result;
    if let Some(byte) = tampered.public_hash.last_mut() {
        *byte ^= 1;
    }

    assert_eq!(
        (
            prover.verify(&result).is_ok(),
            prover.verify(&tampered).err().map(|e| e.to_string()),
            result.public_hash,
            prover.keys().verifying_key().ic.len(),
        ),
        (
            true,
            Some("the proof does not verify under these keys".to_string()),
            to_bytes(native.public_hash()).unwrap(),
            2
        )
    );
}

#[test]
fn the_prover_refuses_a_witness_its_circuit_does_not_accept() {
    let sender = keypair(5);
    let payment = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [
                spendable(&sender, Mint::SOL, 300, 0),
                spendable(&sender, Mint::SOL, 200, 1),
            ],
            amount: 400,
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    };
    let diverging = Groth16Prover::<DivergingPayment>::new_with_test_setup().unwrap();
    let reshaped = Groth16Prover::<ReshapedPayment>::new_with_test_setup().unwrap();

    assert_eq!(
        (
            matches!(
                diverging.prove(&DivergingPayment {
                    payment: payment.clone()
                }),
                Err(RelationError::Unsatisfied(_))
            ),
            reshaped
                .prove(&ReshapedPayment {
                    payment: payment.clone(),
                    extra_input: false,
                })
                .is_ok(),
            reshaped
                .prove(&ReshapedPayment {
                    payment,
                    extra_input: true,
                })
                .err()
                .map(|e| e.to_string()),
        ),
        (
            true,
            true,
            Some("the proof inputs build another circuit than the prover's".to_string()),
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
            tx_context: TxContext::new(),
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
    let spp = payment
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
        )
    );
}

#[test]
fn the_keyless_finalized_transaction_carries_the_circuit_hashes_to_the_key_holder() {
    let sender = keypair(5);
    let sender_address = sender.shielded_address().unwrap();
    let payer = sender_address.solana_address().unwrap();
    let payment = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [
                spendable(&sender, Mint::SOL, 300, 0),
                spendable(&sender, Mint::SOL, 200, 1),
            ],
            amount: 400,
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    };
    let native = payment
        .instantiate(&Allocator::native())
        .unwrap()
        .circuit()
        .unwrap();
    let finalized = payment
        .create_finalized_transaction(&sender_address, payer)
        .unwrap();
    let finalized_hashes = (
        finalized.output_hashes().unwrap(),
        finalized.padding_independent_private_tx_hash().unwrap(),
    );
    let encrypted = finalized.encrypt(&sender).unwrap();
    let one_shot = payment
        .create_proof_inputs_and_encrypt(&sender, payer, u64::MAX)
        .unwrap();
    let hashes = |spp: &SppProofInputs| {
        (
            spp.output_utxos
                .iter()
                .map(|output| output.hash(spp.output_tree_id).unwrap())
                .collect::<Vec<_>>(),
            spp.padding_independent_private_tx_hash().unwrap(),
        )
    };

    assert_eq!(
        (finalized_hashes.1, hashes(&encrypted), hashes(&one_shot),),
        (
            to_bytes(native.private_tx_hash()).unwrap(),
            finalized_hashes.clone(),
            finalized_hashes,
        )
    );
}

#[test]
fn logic_dummies_are_dropped_and_unused_outputs_are_empty_utxos() {
    let first = spendable(&keypair(5), Mint::SOL, 500, 0);
    let recipient = keypair(6).shielded_address().unwrap();
    let sweep = |token_utxos_asset_a, amount| {
        let spp = encrypt(&Sweep {
            private: SweepPrivateInputs {
                tx_context: TxContext::new(),
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
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first],
            owner: owner.shielded_address().unwrap(),
        },
        public: RegisterPublicInputs { label: 42 },
    };
    let spp = encrypt(&register).unwrap();
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
            register.check_constraints().is_ok(),
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
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, spendable(&sender, Mint::SOL, 200, 1)],
            amount: 400,
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    };
    let stranger = keypair(7);
    let mut overspend = honest.clone();
    overspend.private.amount = 600;

    assert_eq!(
        (
            honest
                .create_proof_inputs_and_encrypt(&stranger, Address::new_unique(), u64::MAX)
                .err()
                .map(|e| e.to_string()),
            encrypt(&overspend).err(),
        ),
        (
            Some("output slot 0 has an owner no input names".to_string()),
            Some("the transfer exceeds the balance".to_string()),
        )
    );
}

#[test]
fn the_output_tree_is_the_set_one_or_the_first_inputs_latest_tree() {
    let sender = keypair(5);
    let payment = |output_tree_id: Option<u16>, latest_tree_id: Option<u16>| {
        let mut first = spendable(&sender, Mint::SOL, 300, 0);
        first.latest_tree_id = latest_tree_id;
        Payment {
            private: PaymentPrivateInputs {
                tx_context: TxContext::new().with_output_tree_id(output_tree_id),
                token_utxos_asset_a: [first, spendable(&sender, Mint::SOL, 200, 1)],
                amount: 400,
            },
            public: RecipientPublicInputs {
                recipient: keypair(6).shielded_address().unwrap(),
            },
        }
    };
    let output_tree = |program: Payment| {
        encrypt(&program)
            .map(|spp_proof_inputs| spp_proof_inputs.output_tree_id)
            .and_then(|output_tree_id| {
                program
                    .check_constraints()
                    .map(|_| output_tree_id)
                    .map_err(|e| e.to_string())
            })
    };

    assert_eq!(
        (
            TxContext::new().output_tree_id,
            output_tree(payment(Some(4), Some(9))),
            output_tree(payment(None, Some(9))),
            output_tree(payment(None, None)),
        ),
        (
            Some(0),
            Ok(4),
            Ok(9),
            Err(
                "the first input reports no latest tree and the transaction sets no output tree"
                    .to_string()
            ),
        )
    );
}

#[test]
fn setup_saves_loads_and_exports_the_keys() {
    let sender = keypair(5);
    let first = spendable(&sender, Mint::SOL, 300, 0);
    let payment = Payment {
        private: PaymentPrivateInputs {
            tx_context: TxContext::new(),
            token_utxos_asset_a: [first, spendable(&sender, Mint::SOL, 200, 1)],
            amount: 400,
        },
        public: RecipientPublicInputs {
            recipient: keypair(6).shielded_address().unwrap(),
        },
    };
    let prover = Groth16Prover::<Payment>::new_with_test_setup().unwrap();
    let keys = prover.keys();
    let dir = std::env::temp_dir().join(format!("zk-program-sdk-keys-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let proving_key = dir.join("pk.bin");
    keys.save(&proving_key).unwrap();
    let loaded = Groth16Prover::<Payment>::new(Groth16Keys::load(&proving_key).unwrap()).unwrap();
    let result = loaded.prove(&payment).unwrap();
    let other_circuit = Groth16Prover::<Register>::new(Groth16Keys::load(&proving_key).unwrap())
        .err()
        .map(|e| e.to_string());
    let parsed = parse_gnark_vk_bytes(&keys.gnark_verifying_key().unwrap()).unwrap();
    let parsed_accepts = {
        let public_inputs = [result.public_hash];
        let verifying_key = parsed.as_borrowed();
        Groth16Verifier::new(
            &result.proof.a,
            &result.proof.b,
            &result.proof.c,
            &public_inputs,
            &verifying_key,
        )
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
            loaded.keys().verifying_key() == keys.verifying_key(),
            Groth16Prover::<Payment>::new_with_test_setup()
                .unwrap()
                .keys()
                .verifying_key()
                == keys.verifying_key(),
            prover.verify(&result).is_ok(),
            other_circuit,
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
            true,
            Some("the Groth16 keys belong to another circuit".to_string()),
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
