#![cfg(all(feature = "client", feature = "setup"))]
use solana_address::Address;
use zolana_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};
use zolana_program::{
    circuit::{
        zero, Assert, CheckedTransaction, Circuit, ConfidentialTransaction, DataUtxo, PublicInputs,
        TokenUtxos, UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, Groth16Prover, ProgramOwner, TxContext, ZkProgram,
};
use zolana_transaction::{Mint, WalletUtxo};

#[test]
fn raw_state_commitment_reserves_an_address_and_closes_with_private_padding() {
    // 1. Create the state and reserve its address.
    let viewer =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7; 32])).expect("viewer");
    let sender = viewer.shielded_address().expect("sender");
    let program = ProgramOwner::new(Address::new_from_array([9; 32]));
    let owner = program
        .address(viewer.viewing_pubkey())
        .expect("program address");
    let mut state_hash = [0; 32];
    state_hash[31] = 42;
    let public = StatePublicInputs { owner, state_hash };
    let create = Create {
        private: CreatePrivateInputs {
            tx_context: TxContext::new().with_output_tree_id(Some(0)),
        },
        public: public.clone(),
    };
    let finalized = create
        .create_finalized_transaction(&sender, sender.solana_address().expect("payer"))
        .expect("create transaction");
    assert!(finalized
        .input_utxos()
        .first()
        .expect("address input")
        .is_address());
    assert_eq!(finalized.output_utxos().len(), 2);
    assert!(
        finalized
            .output_utxos()
            .last()
            .expect("padding output")
            .compact
    );
    let encrypted = finalized
        .clone()
        .encrypt_with_viewing_key(&viewer.viewing_key)
        .expect("encrypt create");
    assert_eq!(encrypted.external_data.outputs.len(), 1);
    let output = finalized.output_utxos().first().expect("state output");
    assert_eq!(
        (
            output.asset,
            output.amount,
            output.data_hash,
            output.data.utxo_data()
        ),
        (Mint::SOL, 0, Some(state_hash), None)
    );
    let prover = Groth16Prover::<Create>::new_with_test_setup().expect("create keys");
    prover
        .verify(&prover.prove(&create).expect("create proof"))
        .expect("verify create");
    // 2. Close the state and retain optional deposit padding.
    let close = Close {
        private: ClosePrivateInputs {
            tx_context: TxContext::new().with_output_tree_id(Some(7)),
            state: program.input(output, 0, 0).expect("state input"),
            first: WalletUtxo::dummy(0).expect("first padding"),
            second: WalletUtxo::dummy(0).expect("second padding"),
        },
        public,
    };
    let finalized = close
        .create_finalized_transaction(&sender, sender.solana_address().expect("payer"))
        .expect("close transaction");
    assert_eq!(finalized.input_utxos().len(), 3);
    assert_eq!(finalized.output_tree_id(), 7);
    assert!(finalized
        .input_utxos()
        .iter()
        .all(|input| input.tree_id == 0));
    assert_eq!(finalized.output_utxos().len(), 2);
    assert!(finalized
        .output_utxos()
        .iter()
        .all(|output| !output.is_dummy() && !output.compact && output.amount == 0));
    // 3. Prove and verify the state transition.
    let prover = Groth16Prover::<Close>::new_with_test_setup().expect("close keys");
    prover
        .verify(&prover.prove(&close).expect("close proof"))
        .expect("verify close");
}

#[test]
fn optional_inputs_keep_real_deposits_before_padding_without_changing_refund_order() {
    // 1. Create the state and reserve its address.
    let viewer =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7; 32])).expect("viewer");
    let sender = viewer.shielded_address().expect("sender");
    let program = ProgramOwner::new(Address::new_from_array([9; 32]));
    let owner = program
        .address(viewer.viewing_pubkey())
        .expect("program address");
    let mut state_hash = [0; 32];
    state_hash[31] = 42;
    let public = StatePublicInputs { owner, state_hash };
    let create = Create {
        private: CreatePrivateInputs {
            tx_context: TxContext::new().with_output_tree_id(Some(0)),
        },
        public: public.clone(),
    };
    let created = create
        .create_finalized_transaction(&sender, sender.solana_address().expect("payer"))
        .expect("create transaction");
    let output = created.output_utxos().first().expect("state output");
    let deposit =
        zolana_transaction::SppProofOutputUtxo::new(Mint::SOL, 77, owner).expect("deposit");
    let deposit = program.input(&deposit, 0, 1).expect("deposit input");
    // 2. Check either funded deposit precedes padding.
    for first_funded in [false, true] {
        let dummy = WalletUtxo::dummy(0).expect("padding");
        let (first, second) = if first_funded {
            (deposit.clone(), dummy)
        } else {
            (dummy, deposit.clone())
        };
        let close = Close {
            private: ClosePrivateInputs {
                tx_context: TxContext::new().with_output_tree_id(Some(0)),
                state: program.input(output, 0, 0).expect("state input"),
                first,
                second,
            },
            public: public.clone(),
        };
        let finalized = close
            .create_finalized_transaction(&sender, sender.solana_address().expect("payer"))
            .expect("close transaction");
        let inputs = finalized.input_utxos();
        assert_eq!(inputs.len(), 3);
        assert!(!inputs.get(1).expect("deposit follows state").is_dummy());
        assert!(inputs.get(2).expect("padding is last").is_dummy());
        assert_eq!(
            finalized
                .output_utxos()
                .iter()
                .map(|output| output.amount)
                .collect::<Vec<_>>(),
            if first_funded {
                vec![77, 0]
            } else {
                vec![0, 77]
            }
        );
        zolana_program::ZkCircuit::check_constraints(&close)
            .expect("the private ordering satisfies R1CS");
    }
}

#[derive(Clone, ProofInput)]
pub struct CreatePrivateInputs {
    tx_context: TxContext,
}
#[derive(Clone, PublicInputs)]
pub struct StatePublicInputs {
    owner: ShieldedAddress,
    state_hash: [u8; 32],
}
#[derive(Clone, ZkProgram)]
pub struct Create {
    private: CreatePrivateInputs,
    public: StatePublicInputs,
}
impl Circuit for <Create as ProofInput>::Circuit {
    type Output = CheckedTransaction;
    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let state = DataUtxo::new_init_with_hash(&self.public.owner, &self.public.state_hash);
        ConfidentialTransaction::new(&self.private.tx_context, &self.public)
            .with_compact_padding()
            .with_new_address(&self.public.owner, &self.public.state_hash)
            .with_hashed_data_utxo(state)
            .check()
    }
}
#[derive(Clone, ProofInput)]
pub struct ClosePrivateInputs {
    tx_context: TxContext,
    state: WalletUtxo,
    first: WalletUtxo,
    second: WalletUtxo,
}
#[derive(Clone, ZkProgram)]
pub struct Close {
    private: ClosePrivateInputs,
    public: StatePublicInputs,
}
impl Circuit for <Close as ProofInput>::Circuit {
    type Output = CheckedTransaction;
    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let state = DataUtxo::new_close_with_hash(&self.private.state, &self.public.state_hash)?;
        state
            .amount()?
            .var()
            .assert_equal(&zero(), "the state holds no tokens")?;
        let mut first = TokenUtxos::new_optional_close(
            &self.private.first,
            &self.public.owner,
            &state.asset(),
        )?;
        let mut second = TokenUtxos::new_optional_close(
            &self.private.second,
            &self.public.owner,
            &state.asset(),
        )?;
        let mut first_refund =
            TokenUtxos::new_init(&self.public.owner, &state.asset()).with_zero_output();
        let mut second_refund =
            TokenUtxos::new_init(&self.public.owner, &state.asset()).with_zero_output();
        first.transfer_all(&mut first_refund)?;
        second.transfer_all(&mut second_refund)?;
        ConfidentialTransaction::new(&self.private.tx_context, &self.public)
            .with_input_padding()
            .with_hashed_data_utxo(state)
            .with_optional_token_utxos([first, second])
            .with_token_utxos(first_refund)
            .with_token_utxos(second_refund)
            .check()
    }
}
