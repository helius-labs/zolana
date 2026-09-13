use borsh::{BorshDeserialize, BorshSerialize};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ProoflessOutput {
    pub owner: [u8; 32],
    pub blinding: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
    pub data_hash: Option<[u8; 32]>,
    pub utxo_data: Option<Vec<u8>>,
    pub ring_program_id: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    pub ring_data: Option<Vec<u8>>,
    /// Optional free-form memo, emitted in the clear. Not committed into any
    /// hash, so it is informational only.
    pub memo: Option<Vec<u8>>,
}

/// Borrowed serialization view of [`ProoflessOutput`].
///
/// This has the same Borsh representation as the owned type while allowing an
/// on-chain processor to write instruction-backed payloads directly into the
/// final encoded output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize)]
pub struct ProoflessOutputRef<'a> {
    pub owner: &'a [u8; 32],
    pub blinding: &'a [u8; 32],
    pub asset: &'a [u8; 32],
    pub amount: u64,
    pub data_hash: Option<&'a [u8; 32]>,
    pub utxo_data: Option<&'a [u8]>,
    pub ring_program_id: Option<&'a [u8; 32]>,
    pub ring_data_hash: Option<&'a [u8; 32]>,
    pub ring_data: Option<&'a [u8]>,
    pub memo: Option<&'a [u8]>,
}

/// Encryption record for one owner-hidden ring deposit: sent in `ring_deposit`
/// instruction data (wincode) and republished in the output payload (borsh).
#[derive(
    Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, SchemaRead, SchemaWrite,
)]
pub struct EncryptedRingDepositData {
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; 16],
    #[wincode(with = "containers::Vec<u8, FixIntLen<u16>>")]
    pub ciphertext: Vec<u8>,
}

/// Borrowed view of [`EncryptedRingDepositData`]: read from the instruction
/// buffer, written into the output payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, SchemaRead)]
pub struct EncryptedRingDepositDataRef<'a> {
    pub tx_viewing_pk: &'a [u8; 33],
    pub salt: &'a [u8; 16],
    pub ciphertext: &'a [u8],
}

/// Output body for an owner-hidden policy-ring deposit. Settlement and
/// commitment fields remain visible; private preimages live in `encrypted`.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct EncryptedRingDepositOutput {
    pub owner_utxo_hash: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
    pub data_hash: Option<[u8; 32]>,
    pub ring_program_id: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub encrypted: EncryptedRingDepositData,
}

/// Borrowed serialization view of [`EncryptedRingDepositOutput`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize)]
pub struct EncryptedRingDepositOutputRef<'a> {
    pub owner_utxo_hash: &'a [u8; 32],
    pub asset: &'a [u8; 32],
    pub amount: u64,
    pub data_hash: Option<&'a [u8; 32]>,
    pub ring_program_id: &'a [u8; 32],
    pub ring_data_hash: &'a [u8; 32],
    pub encrypted: EncryptedRingDepositDataRef<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub enum OutputDataEncoding {
    Plaintext(Vec<u8>),
    Encrypted(Vec<u8>),
    VerifiablyEncrypted(Vec<u8>),
}

/// Scheme byte inside [`OutputDataEncoding::Encrypted`] for owner-hidden
/// policy-ring deposits.
pub const ENCRYPTED_RING_DEPOSIT_SCHEME: u8 = 8;

impl OutputDataEncoding {
    pub const PLAINTEXT_TAG: u8 = 0;
    pub const ENCRYPTED_TAG: u8 = 1;
}

/// First byte of the encrypted payload for the confidential encryption scheme.
///
/// Kept here (rather than depending on the SDK serialization crate) so the
/// on-chain program can recognize the marker without allocating or decoding
/// the ciphertext.
pub const CONFIDENTIAL_ENCRYPTED_SCHEME_TAG: u8 = 3;

pub const RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG: u8 = 4;

/// Returns whether `data` is a structurally valid encrypted output whose first
/// payload byte selects the confidential encryption scheme.
pub fn is_confidential_encrypted_output(data: &[u8]) -> bool {
    confidential_encrypted_output_body(data).is_some()
}

pub fn confidential_encrypted_output_body(data: &[u8]) -> Option<&[u8]> {
    encrypted_output_body(data, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG)
}

pub fn ring_confidential_encrypted_output_body(data: &[u8]) -> Option<&[u8]> {
    encrypted_output_body(data, RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG)
}

fn encrypted_output_body(data: &[u8], scheme: u8) -> Option<&[u8]> {
    let (&encoding_tag, rest) = data.split_first()?;
    if encoding_tag != OutputDataEncoding::ENCRYPTED_TAG {
        return None;
    }
    let (len_bytes, body) = rest.split_first_chunk::<4>()?;
    let body_len = usize::try_from(u32::from_le_bytes(*len_bytes)).ok()?;
    let (&scheme_byte, payload) = body.split_first()?;
    (body_len == body.len() && scheme_byte == scheme).then_some(payload)
}

/// Encodes a proofless deposit output: `Plaintext(scheme 0 || borsh(ProoflessOutput))`.
pub fn encode_output_data(data: ProoflessOutput) -> Vec<u8> {
    encode_output_data_ref(ProoflessOutputRef {
        owner: &data.owner,
        blinding: &data.blinding,
        asset: &data.asset,
        amount: data.amount,
        data_hash: data.data_hash.as_ref(),
        utxo_data: data.utxo_data.as_deref(),
        ring_program_id: data.ring_program_id.as_ref(),
        ring_data_hash: data.ring_data_hash.as_ref(),
        ring_data: data.ring_data.as_deref(),
        memo: data.memo.as_deref(),
    })
}

/// Borrowed counterpart of [`encode_output_data`].
pub fn encode_output_data_ref(data: ProoflessOutputRef<'_>) -> Vec<u8> {
    let variable_len = data.utxo_data.map_or(0, <[u8]>::len)
        + data.ring_data.map_or(0, <[u8]>::len)
        + data.memo.map_or(0, <[u8]>::len);
    encode_tagged_body(
        OutputDataEncoding::PLAINTEXT_TAG,
        PLAINTEXT_SCHEME,
        PLAINTEXT_OUTPUT_FIXED_LEN + variable_len,
        |out| data.serialize(out),
    )
}

const PLAINTEXT_SCHEME: u8 = 0;
const BODY_LEN_OFFSET: usize = 1;
const BODY_OFFSET: usize = BODY_LEN_OFFSET + 4;

/// Encoded length of a plaintext output with every option present and every
/// variable-length field empty: encoding tag, `u32` body length, scheme byte,
/// then the borsh body. Variable-length bytes add on top.
pub const PLAINTEXT_OUTPUT_FIXED_LEN: usize = 224;

/// Encoded length of an owner-hidden ring deposit output with `data_hash`
/// present and an empty ciphertext; ciphertext bytes add on top.
pub const ENCRYPTED_RING_DEPOSIT_OUTPUT_FIXED_LEN: usize = 228;

/// Writes `OutputDataEncoding::<tag>(scheme || body)` into one buffer: the
/// `u32` body length is patched in after the body is serialized, so the body is
/// not serialized into a temporary and copied into the enum payload.
fn encode_tagged_body(
    encoding_tag: u8,
    scheme: u8,
    capacity: usize,
    write_body: impl FnOnce(&mut Vec<u8>) -> borsh::io::Result<()>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    out.push(encoding_tag);
    out.extend_from_slice(&[0u8; 4]);
    out.push(scheme);
    write_body(&mut out).expect("shielded-pool output data serialization is infallible");
    let body_len = out
        .len()
        .checked_sub(BODY_OFFSET)
        .and_then(|len| u32::try_from(len).ok())
        .expect("shielded-pool output data length fits in u32");
    out.get_mut(BODY_LEN_OFFSET..BODY_OFFSET)
        .expect("length prefix written above")
        .copy_from_slice(&body_len.to_le_bytes());
    out
}

/// Encodes the mixed public/encrypted payload used by `ring_deposit`.
pub fn encode_encrypted_ring_deposit_output(data: EncryptedRingDepositOutput) -> Vec<u8> {
    encode_encrypted_ring_deposit_output_ref(EncryptedRingDepositOutputRef {
        owner_utxo_hash: &data.owner_utxo_hash,
        asset: &data.asset,
        amount: data.amount,
        data_hash: data.data_hash.as_ref(),
        ring_program_id: &data.ring_program_id,
        ring_data_hash: &data.ring_data_hash,
        encrypted: EncryptedRingDepositDataRef {
            tx_viewing_pk: &data.encrypted.tx_viewing_pk,
            salt: &data.encrypted.salt,
            ciphertext: &data.encrypted.ciphertext,
        },
    })
}

pub fn encode_encrypted_ring_deposit_output_ref(
    data: EncryptedRingDepositOutputRef<'_>,
) -> Vec<u8> {
    encode_tagged_body(
        OutputDataEncoding::ENCRYPTED_TAG,
        ENCRYPTED_RING_DEPOSIT_SCHEME,
        ENCRYPTED_RING_DEPOSIT_OUTPUT_FIXED_LEN + data.encrypted.ciphertext.len(),
        |out| data.serialize(out),
    )
}
