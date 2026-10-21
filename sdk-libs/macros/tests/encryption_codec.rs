use borsh::{BorshDeserialize, BorshSerialize};
use solana_address::Address;
use zolana_keypair::ViewingKey;
use zolana_program::{
    circuit::{poseidon, CircuitType, CircuitVar, DataHash, UtxoData, UtxoState},
    conversion::{to_bytes, Allocator, ProofInput},
    hasher::{data_hash, unique_data_hash, DataHasher, Hasher, HasherError, Poseidon, ToByteArray},
    CircuitError, DataUtxo, EncryptionCodec, ProgramOwner,
};
use zolana_transaction::{Mint, SppProofOutputUtxo, WalletUtxo};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
#[utxo_state(custom_codec)]
struct CompactState {
    value: u64,
    doubled: u64,
}

impl EncryptionCodec for CompactState {
    fn serialize_for_encryption(&self) -> std::io::Result<Vec<u8>> {
        borsh::to_vec(&self.value)
    }

    fn deserialize_after_decryption(bytes: &[u8]) -> std::io::Result<Self> {
        let value = u64::try_from_slice(bytes)?;
        let doubled = value.checked_mul(2).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "doubled value overflows")
        })?;
        Ok(Self { value, doubled })
    }
}

// Custom codecs do not require the state itself to implement either Borsh trait.
#[derive(Clone, Debug, UtxoState)]
#[utxo_state(custom_codec)]
struct BrokenCodec<const MODE: u8> {
    value: u64,
}

impl<const MODE: u8> EncryptionCodec for BrokenCodec<MODE> {
    fn serialize_for_encryption(&self) -> std::io::Result<Vec<u8>> {
        if MODE == 1 {
            return Err(std::io::Error::other("encode failed"));
        }
        borsh::to_vec(&self.value)
    }

    fn deserialize_after_decryption(bytes: &[u8]) -> std::io::Result<Self> {
        if MODE == 2 {
            return Err(std::io::Error::other("decode failed"));
        }
        Ok(Self {
            value: if MODE == 0 {
                0
            } else {
                u64::try_from_slice(bytes)?
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
struct GenericState<const N: usize> {
    values: [u64; N],
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, CircuitType)]
struct NestedLossy {
    value: u64,
    #[borsh(skip)]
    doubled: u64,
}

impl ToByteArray for NestedLossy {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[&self.value.to_byte_array()?, &self.doubled.to_byte_array()?])
    }
}

impl DataHash for NestedLossyCircuit {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        poseidon(&[self.value.var(), self.doubled.var()])
    }
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, UtxoState)]
struct NestedState {
    data: NestedLossy,
}

fn native<T: ProofInput>(state: &T) -> T::Circuit {
    state
        .instantiate(&Allocator::native())
        .expect("instantiate")
}

fn wallet<T: DataHasher>(state: &T, address: Option<[u8; 32]>, payload: &[u8]) -> WalletUtxo {
    let owner = ProgramOwner::new(Address::new_from_array([9; 32]));
    let viewer = ViewingKey::from_bytes(&[7; 32]);
    let recipient = owner.address(viewer.pubkey()).expect("recipient");
    let state_hash = state.hash().expect("state hash");
    let (encoded, hash) = match address {
        None => (payload.to_vec(), data_hash(&state_hash).expect("data hash")),
        Some(address) => {
            let mut bytes = address.to_vec();
            bytes.extend_from_slice(payload);
            (
                bytes,
                unique_data_hash(&address, &state_hash).expect("unique hash"),
            )
        }
    };
    let output = SppProofOutputUtxo::new(Mint::SOL, 0, recipient)
        .expect("output")
        .with_utxo_data(encoded, hash);
    owner.input(&output, 0, 0).expect("input")
}

#[test]
fn compact_payload_reconstructs_the_full_state_and_its_commitment() {
    let state = CompactState {
        value: 21,
        doubled: 42,
    };
    let circuit = native(&state);
    let payload = circuit.utxo_data().expect("validated payload");
    let decoded = CompactState::deserialize_after_decryption(&payload).expect("decode");
    assert_eq!(
        (
            payload,
            borsh::to_vec(&state).expect("full state"),
            decoded,
            to_bytes(&DataHash::hash(&circuit).expect("circuit hash")).expect("hash bytes"),
        ),
        (
            borsh::to_vec(&21u64).expect("compact bytes"),
            borsh::to_vec(&(21u64, 42u64)).expect("full bytes"),
            state.clone(),
            state.hash().expect("native hash"),
        )
    );
}

#[test]
fn compact_payloads_decode_in_ordinary_and_addressed_utxos() {
    let state = CompactState {
        value: 21,
        doubled: 42,
    };
    let payload = native(&state).utxo_data().expect("payload");
    for address in [None, Some([3; 32])] {
        let decoded = DataUtxo::<CompactState>::try_from(wallet(&state, address, &payload))
            .expect("decoded utxo");
        assert_eq!((decoded.data, decoded.address), (state.clone(), address));
    }
}

#[test]
fn tampered_compact_payloads_fail_commitment_verification() {
    let state = CompactState {
        value: 21,
        doubled: 42,
    };
    let payload = borsh::to_vec(&22u64).expect("tampered payload");
    for address in [None, Some([3; 32])] {
        let error = DataUtxo::<CompactState>::try_from(wallet(&state, address, &payload))
            .expect_err("tampering must fail");
        assert_eq!(error.name(), "ClientError.DataHashMismatch");
    }
}

#[test]
fn compact_payloads_reject_truncated_trailing_and_unreconstructible_bytes() {
    let state = CompactState {
        value: 21,
        doubled: 42,
    };
    let payload = state.serialize_for_encryption().expect("encode");
    let mut trailing = payload.clone();
    trailing.push(0);
    for invalid in [
        payload[..payload.len() - 1].to_vec(),
        trailing,
        borsh::to_vec(&u64::MAX).expect("overflow payload"),
    ] {
        for address in [None, Some([3; 32])] {
            let error = DataUtxo::<CompactState>::try_from(wallet(&state, address, &invalid))
                .expect_err("invalid payload must fail");
            assert_eq!(error.name(), "ClientError.UtxoDataEncoding");
        }
    }
}

#[test]
fn outputs_reject_codecs_that_lose_committed_data() {
    let error = native(&BrokenCodec::<0> { value: 7 })
        .utxo_data()
        .expect_err("lossy codec must fail");
    assert_eq!(error.name(), "CircuitError.StateRoundTripMismatch");
}

#[test]
fn the_default_codec_rejects_lossy_serialization_inside_nested_fields() {
    let state = NestedState {
        data: NestedLossy {
            value: 21,
            doubled: 42,
        },
    };
    let error = native(&state)
        .utxo_data()
        .expect_err("nested skipped data must fail");
    assert_eq!(error.name(), "CircuitError.StateRoundTripMismatch");
}

#[test]
fn outputs_report_codec_serialization_errors() {
    let error = native(&BrokenCodec::<1> { value: 7 })
        .utxo_data()
        .expect_err("encode must fail");
    assert_eq!(error.name(), "CircuitError.StateEncoding");
}

#[test]
fn outputs_report_codec_reconstruction_errors() {
    let error = native(&BrokenCodec::<2> { value: 7 })
        .utxo_data()
        .expect_err("decode must fail");
    assert_eq!(error.name(), "CircuitError.StateEncoding");
}

#[test]
fn custom_codecs_work_without_borsh_implementations_on_the_state() {
    let state = BrokenCodec::<3> { value: 7 };
    let encoded = native(&state).utxo_data().expect("custom codec");
    let decoded = DataUtxo::<BrokenCodec<3>>::try_from(wallet(&state, None, &encoded))
        .expect("custom state without Borsh");
    assert_eq!(decoded.data.value, state.value);
}

#[test]
fn generic_states_keep_the_default_borsh_codec() {
    let state = GenericState { values: [1, 2] };
    let encoded = native(&state).utxo_data().expect("generic payload");
    assert_eq!(
        (
            encoded.clone(),
            GenericState::<2>::deserialize_after_decryption(&encoded).expect("generic decode"),
        ),
        (borsh::to_vec(&state).expect("borsh"), state)
    );
}
