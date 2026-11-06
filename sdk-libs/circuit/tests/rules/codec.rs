//! The commitment check on a state's encryption codec, which every data
//! output runs before its payload is accepted.

use borsh::{BorshDeserialize, io};
use spr_circuit::protocol::{
    ConfidentialTransaction, DataHash, DataUtxo, UniqueDataUtxo, UtxoData,
};
use spr_circuit::{CircuitError, CircuitErrorKind, EncryptionCodec, Field, poseidon, to_bytes};

use crate::support::{Public, context, owner, program_owner};

/// Commits to both values but encrypts only the first and recomputes the
/// second, with `MODE` selecting a codec defect.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Compact<const MODE: u8> {
    value: u64,
    doubled: u64,
}

const SOUND: u8 = 0;
const LOSSY: u8 = 1;
const ENCODE_FAILS: u8 = 2;
const DECODE_FAILS: u8 = 3;

impl<const MODE: u8> DataHash for Compact<MODE> {
    fn hash(&self) -> Result<Field, CircuitError> {
        poseidon(&[Field::from(self.value), Field::from(self.doubled)])
    }
}

impl<const MODE: u8> EncryptionCodec for Compact<MODE> {
    fn serialize_for_encryption(&self) -> io::Result<Vec<u8>> {
        if MODE == ENCODE_FAILS {
            return Err(io::Error::other("encode failed"));
        }
        borsh::to_vec(&self.value)
    }

    fn deserialize_after_decryption(bytes: &[u8]) -> io::Result<Self> {
        if MODE == DECODE_FAILS {
            return Err(io::Error::other("decode failed"));
        }
        let value = u64::try_from_slice(bytes)?;
        let doubled = if MODE == LOSSY { 0 } else { value * 2 };
        Ok(Self { value, doubled })
    }
}

impl<const MODE: u8> UtxoData for Compact<MODE> {}

fn compact<const MODE: u8>() -> Compact<MODE> {
    Compact {
        value: 21,
        doubled: 42,
    }
}

#[test]
fn a_sound_codec_payload_is_the_encoded_state() {
    assert_eq!(
        compact::<SOUND>().utxo_data(),
        Ok(borsh::to_vec(&21u64).unwrap())
    );
}

#[test]
fn a_codec_that_loses_or_fails_to_encode_the_state_is_refused() {
    assert_eq!(
        [
            compact::<LOSSY>().utxo_data().unwrap_err().kind().clone(),
            compact::<ENCODE_FAILS>()
                .utxo_data()
                .unwrap_err()
                .kind()
                .clone(),
            compact::<DECODE_FAILS>()
                .utxo_data()
                .unwrap_err()
                .kind()
                .clone(),
        ],
        [
            CircuitErrorKind::InvalidInput("state encoding changes its commitment"),
            CircuitErrorKind::InvalidInput("state encoding failed"),
            CircuitErrorKind::InvalidInput("state decoding failed"),
        ]
    );
}

#[test]
fn outputs_carry_the_payload_and_unique_outputs_prefix_their_address() {
    let mut state = DataUtxo::<Compact<SOUND>>::new_init(&owner(1));
    *state = compact();
    let mut unique =
        UniqueDataUtxo::<Compact<SOUND>>::new_init(&program_owner(2), &Field::one()).unwrap();
    *unique = compact();
    let mut addressed = to_bytes(&unique.address()).to_vec();
    addressed.extend(borsh::to_vec(&21u64).unwrap());
    let checked = ConfidentialTransaction::new(&context(), &Public)
        .with(unique)
        .with(state)
        .check()
        .unwrap();
    assert_eq!(
        checked
            .outputs
            .iter()
            .map(|output| output.output.data.clone())
            .collect::<Vec<_>>(),
        vec![Some(addressed), Some(borsh::to_vec(&21u64).unwrap())]
    );
}

#[test]
fn a_refused_payload_fails_the_transaction() {
    let mut state = DataUtxo::<Compact<LOSSY>>::new_init(&owner(1));
    *state = compact();
    let mut unique =
        UniqueDataUtxo::<Compact<LOSSY>>::new_init(&program_owner(2), &Field::one()).unwrap();
    *unique = compact();
    for result in [
        ConfidentialTransaction::new(&context(), &Public)
            .with(unique)
            .check(),
        ConfidentialTransaction::new(&context(), &Public)
            .with(spr_circuit::protocol::NewAddress::new(&program_owner(2), &Field::one()).unwrap())
            .with(state)
            .check(),
    ] {
        assert_eq!(
            result.unwrap_err().kind(),
            &CircuitErrorKind::InvalidInput("state encoding changes its commitment")
        );
    }
}
