use borsh::BorshDeserialize;
use solana_address::Address;
use spr_event::OutputDataEncoding;
use spr_keypair::{NullifierKey, PublicKey, ShieldedAddress, ViewingKey};
use spr_program::{
    circuit::{
        CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction, PublicHashOutput,
        PublicInputs, TokenUtxos, UtxoTrait,
    },
    conversion::ProofInput,
    CircuitError, Groth16Prover, ProgramOwner, R1cs, TxContext, ZkCircuit, ZkProgramCircuit,
};
use spr_transaction::{
    instructions::transact::SppProofInputs,
    serialization::{
        confidential::{Confidential, ConfidentialOutputPlaintext},
        DecodeCx, UtxoSerialization,
    },
    Mint, SppProofOutputUtxo, TransactionError, WalletUtxo,
};

#[test]
fn selected_destinations_keep_their_own_viewing_keys() {
    for select_first in [false, true] {
        // 1. Select between two viewing keys for the same owner.
        let (program, sender) = fixture(select_first, true);
        let expected = if select_first {
            program.private.destinations
        } else {
            [
                program.private.destinations[1],
                program.private.destinations[0],
            ]
        };
        let finalized = program
            .create_finalized_transaction(&sender, Address::default())
            .unwrap();
        assert_eq!(
            finalized
                .output_utxos()
                .iter()
                .map(|output| output.owner_address)
                .collect::<Vec<_>>(),
            expected.map(Some)
        );

        // 2. Encrypt each output and recover it with its selected viewing key.
        let output_fields = finalized.output_utxos().to_vec();
        let encrypted = finalized
            .encrypt_with_viewing_key(&ViewingKey::from_bytes(&[20; 32]))
            .unwrap();
        for (index, address) in expected.iter().enumerate() {
            let seed = if address.viewing_pubkey == ViewingKey::from_bytes(&[11; 32]).pubkey() {
                11
            } else {
                13
            };
            let key = ViewingKey::from_bytes(&[seed; 32]);
            let recovered = plaintext_at(&encrypted, &key, index).unwrap();
            let fields = output_fields.get(index).unwrap();
            let expected = ConfidentialOutputPlaintext {
                asset_id: fields.asset.asset_id,
                amount: fields.amount,
                blinding: fields.blinding,
                ring_program_id: fields.ring_program_id,
                data: fields.data.clone(),
            };
            assert_eq!(recovered, expected);
            let other = ViewingKey::from_bytes(&[if seed == 11 { 13 } else { 11 }; 32]);
            if let Ok(wrong) = plaintext_at(&encrypted, &other, index) {
                assert_ne!(wrong, expected);
            }
        }
    }
}

#[test]
fn distinct_owners_keep_their_addresses() {
    for select_first in [false, true] {
        let (program, sender) = fixture(select_first, false);
        let expected = if select_first {
            program.private.destinations
        } else {
            [
                program.private.destinations[1],
                program.private.destinations[0],
            ]
        };
        let finalized = program
            .create_finalized_transaction(&sender, Address::default())
            .unwrap();
        assert_eq!(
            finalized
                .output_utxos()
                .iter()
                .map(|output| output.owner_address)
                .collect::<Vec<_>>(),
            expected.map(Some)
        );
    }
}

#[test]
fn private_selection_keeps_one_r1cs_shape() {
    let (first, _) = fixture(true, true);
    let (second, _) = fixture(false, true);
    let bytes = TwoPayments::export_r1cs().unwrap();
    let constraints = R1cs::from_bytes(&bytes).unwrap().constraints();
    assert_eq!(first.check_constraints().unwrap(), constraints);
    assert_eq!(second.check_constraints().unwrap(), constraints);
}

#[test]
fn address_bindings_resolve_clones_and_refuse_ambiguous_hashes() {
    use spr_program::{
        circuit::UtxoOwner,
        conversion::{Allocator, OwnerRecords},
    };

    // 1. Keep distinct viewing addresses even though their owner hashes match.
    let first = destination(11, 11);
    let second = destination(11, 13);
    let allocator = Allocator::native();
    let first_owner = first.instantiate(&allocator).unwrap();
    let second_owner = second.instantiate(&allocator).unwrap();
    let records = allocator.into_records();
    let owners = records.get::<OwnerRecords>().unwrap();
    assert_eq!(owners.get_for(&first_owner.clone()).unwrap(), Some(&first));
    assert_eq!(
        owners.get_for(&second_owner.clone()).unwrap(),
        Some(&second)
    );

    // 2. Refuse to guess a viewing address after its binding is discarded.
    let unbound = UtxoOwner::new(
        first_owner.key().clone(),
        first_owner.nullifier_pk().clone(),
    );
    let error = owners.get_for(&unbound).unwrap_err();
    assert_eq!(error.name(), "CircuitError.AmbiguousOwnerAddress");
}

#[test]
fn a_unique_hash_still_resolves_a_reconstructed_owner() {
    use spr_program::{
        circuit::UtxoOwner,
        conversion::{Allocator, OwnerRecords},
    };

    let address = destination(11, 11);
    let allocator = Allocator::native();
    let owner = address.instantiate(&allocator).unwrap();
    let records = allocator.into_records();
    let unbound = UtxoOwner::new(owner.key().clone(), owner.nullifier_pk().clone());
    assert_eq!(
        records
            .get::<OwnerRecords>()
            .unwrap()
            .get_for(&unbound)
            .unwrap(),
        Some(&address)
    );
}

#[derive(Clone, ProofInput)]
struct AddressChoice {
    destinations: [ShieldedAddress; 2],
    choose_first: bool,
}

struct ChosenAddressHash(CircuitVar);

impl PublicHashOutput for ChosenAddressHash {
    fn public_hash(&self) -> &CircuitVar {
        &self.0
    }
}

impl Circuit for AddressChoiceCircuit {
    type Output = ChosenAddressHash;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let chosen = self
            .choose_first
            .select(&self.destinations[0], &self.destinations[1]);
        Ok(ChosenAddressHash(chosen.hash()?))
    }
}

#[test]
fn selected_public_address_binds_the_viewer_in_one_r1cs_shape() {
    let destinations = [destination(11, 11), destination(11, 13)];
    let chosen = |choose_first| AddressChoice {
        destinations,
        choose_first,
    };
    let first = chosen(true);
    let second = chosen(false);
    let constraints = first.check_constraints().unwrap();
    assert_eq!(second.check_constraints().unwrap(), constraints);
    let prover = Groth16Prover::<AddressChoice>::new_with_test_setup().unwrap();
    let first_proof = prover.prove(&first).unwrap();
    let second_proof = prover.prove(&second).unwrap();
    prover.verify(&first_proof).unwrap();
    prover.verify(&second_proof).unwrap();
    assert_ne!(first_proof.public_inputs, second_proof.public_inputs);
    assert_eq!(
        first_proof.public_inputs,
        vec![destinations[0].address_hash().unwrap()]
    );
    assert_eq!(
        second_proof.public_inputs,
        vec![destinations[1].address_hash().unwrap()]
    );
}

#[derive(Clone, ZkProgramCircuit)]
pub struct TwoPayments {
    private: PaymentInputs,
    public: PaymentPublicInputs,
}
#[derive(Clone, ProofInput)]
pub struct PaymentInputs {
    tx_context: TxContext,
    deposit: WalletUtxo,
    destinations: [ShieldedAddress; 2],
    select_first: bool,
    first_amount: u64,
}
#[derive(Clone, PublicInputs)]
pub struct PaymentPublicInputs {
    nonce: [u8; 32],
}
impl Circuit for <TwoPayments as ProofInput>::Circuit {
    type Output = CheckedTransaction;
    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let private = &self.private;
        let first = private
            .select_first
            .select(&private.destinations[0], &private.destinations[1]);
        let second = private
            .select_first
            .select(&private.destinations[1], &private.destinations[0]);
        let mut deposit = TokenUtxos::new_mut(core::array::from_ref(&private.deposit))?.close();
        let asset = deposit.asset();
        let mut first = TokenUtxos::new_init(&first, &asset);
        let mut second = TokenUtxos::new_init(&second, &asset);
        deposit.transfer(&mut first, &private.first_amount)?;
        deposit.transfer_all(&mut second)?;
        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with(deposit)
            .with(first)
            .with(second)
            .check()
    }
}

fn fixture(select_first: bool, same_owner: bool) -> (TwoPayments, ShieldedAddress) {
    let owner = ProgramOwner::new(Address::new_from_array([9; 32]));
    let sender = owner
        .address(ViewingKey::from_bytes(&[6; 32]).pubkey())
        .unwrap();
    let mut output = SppProofOutputUtxo::new(Mint::SOL, 30, sender).unwrap();
    output.blinding = field(21);
    let first = destination(11, 11);
    let second = destination(if same_owner { 11 } else { 13 }, 13);
    (
        TwoPayments {
            private: PaymentInputs {
                tx_context: TxContext::new()
                    .with_blinding_seed(field(77))
                    .with_output_tree_id(Some(7)),
                deposit: owner.input(&output, 4, 5).unwrap(),
                destinations: [first, second],
                select_first,
                first_amount: 10,
            },
            public: PaymentPublicInputs { nonce: field(1) },
        },
        sender,
    )
}
fn destination(owner: u8, viewing: u8) -> ShieldedAddress {
    ShieldedAddress {
        signing_pubkey: PublicKey::from_ed25519(&[owner; 32]),
        nullifier_pubkey: NullifierKey::from_secret([owner; 31]).pubkey().unwrap(),
        viewing_pubkey: ViewingKey::from_bytes(&[viewing; 32]).pubkey(),
    }
}
fn field(value: u8) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[31] = value;
    bytes
}
fn plaintext_at(
    inputs: &SppProofInputs,
    key: &ViewingKey,
    slot: usize,
) -> Result<ConfidentialOutputPlaintext, TransactionError> {
    let data = inputs
        .external_data
        .outputs
        .get(slot)
        .unwrap()
        .data
        .as_ref()
        .unwrap();
    let OutputDataEncoding::Encrypted(blob) = OutputDataEncoding::try_from_slice(data).unwrap()
    else {
        panic!("confidential output expected")
    };
    let (scheme, body) = blob.split_first().unwrap();
    assert_eq!(*scheme, Confidential::SCHEME.as_byte());
    Confidential::decode(
        body,
        &DecodeCx {
            viewing_key: key,
            tx_viewing_pk: Some(
                spr_keypair::X25519Pubkey::from_bytes(inputs.external_data.tx_viewing_pk).unwrap(),
            ),
            salt: Some(inputs.external_data.salt),
            slot_index: slot as u32,
            first_nullifier: None,
        },
    )
}
