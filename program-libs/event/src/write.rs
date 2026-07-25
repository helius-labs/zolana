//! One-pass encoder for the proofless deposit [`crate::GeneralEvent`].
//!
//! Building the event as a struct and serializing it copies each output's
//! plaintext twice: once into that output's own `data` vector, and again when the
//! event's `outputs` are serialized. Here the encoded length is computed first,
//! so the whole event is appended into a single exactly-sized allocation and
//! every byte is written once.
//!
//! The bytes are the borsh encoding of the equivalent [`crate::GeneralEvent`],
//! so indexers and wallets parse it with the derived implementation as before.
//! `program-libs/event/tests/event_write.rs` pins that equivalence.

use crate::{tag, DepositWithdraw, EventKind, ProoflessOutput};

/// Encoding a length that borsh represents as a `u32` failed. Unreachable for
/// events built from instruction data, which a transaction bounds far below
/// `u32::MAX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventLengthOverflow;

/// One output slot of a proofless deposit event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProoflessOutputSlot {
    pub view_tag: [u8; 32],
    pub utxo_hash: [u8; 32],
    pub output: ProoflessOutput,
}

/// A proofless deposit event: outputs in slot order plus one public-movement
/// record per settled asset. The fields a deposit never uses (spent inputs,
/// published messages, the shared viewing key and salt, the relay fee) are
/// written as their empty encodings.
pub struct ProoflessEvent<'a> {
    pub outputs: &'a [ProoflessOutputSlot],
    pub deposit_withdraws: &'a [DepositWithdraw],
    pub first_output_leaf_index: u64,
    pub output_tree: [u8; 32],
}

/// Borsh's length prefix for a sequence.
const LEN_PREFIX: usize = 4;
/// Borsh's `Option` discriminant.
const OPTION_TAG: usize = 1;
/// `OutputDataEncoding::Plaintext` enum discriminant plus the plaintext scheme
/// byte that opens its payload.
const PLAINTEXT_TAGS: usize = 2;

impl ProoflessEvent<'_> {
    /// Encode as `[EMIT_EVENT, kind, borsh(GeneralEvent)]`, allocating once.
    pub fn encode(&self, kind: EventKind) -> Result<Vec<u8>, EventLengthOverflow> {
        let encoded_len = self.encoded_len()?;
        let mut out = Vec::with_capacity(2 + encoded_len);
        out.push(tag::EMIT_EVENT);
        out.push(kind as u8);
        self.write_body(&mut out)?;
        Ok(out)
    }

    /// Encoded length of the event body, excluding the instruction and kind tags.
    pub fn encoded_len(&self) -> Result<usize, EventLengthOverflow> {
        let mut len = LEN_PREFIX; // inputs: always empty
        len = add(len, LEN_PREFIX)?; // outputs length prefix
        for slot in self.outputs {
            len = add(len, slot_len(slot)?)?;
        }
        len = add(len, LEN_PREFIX)?; // messages: always empty
        len = add(len, 33)?; // tx_viewing_pk
        len = add(len, 16)?; // salt
        len = add(len, 8)?; // first_output_leaf_index
        len = add(len, 32)?; // output_tree
        len = add(len, OPTION_TAG)?; // relay_fee: always None
        len = add(len, LEN_PREFIX)?; // deposit_withdraws length prefix
        for record in self.deposit_withdraws {
            len = add(len, deposit_withdraw_len(record))?;
        }
        Ok(len)
    }

    fn write_body(&self, out: &mut Vec<u8>) -> Result<(), EventLengthOverflow> {
        write_len(out, 0)?; // inputs
        write_len(out, self.outputs.len())?;
        for slot in self.outputs {
            out.extend_from_slice(&slot.view_tag);
            out.extend_from_slice(&slot.utxo_hash);
            // `OutputUtxo::data` is a byte vector holding the encoded output, so
            // its length prefix wraps the plaintext encoding below.
            let output_len = proofless_output_len(&slot.output)?;
            write_len(out, add(PLAINTEXT_TAGS + LEN_PREFIX, output_len)?)?;
            out.push(0); // OutputDataEncoding::Plaintext
            write_len(out, add(1, output_len)?)?; // scheme byte plus the output
            out.push(0); // plaintext scheme
            write_proofless_output(out, &slot.output)?;
        }
        write_len(out, 0)?; // messages
        out.extend_from_slice(&[0u8; 33]); // tx_viewing_pk
        out.extend_from_slice(&[0u8; 16]); // salt
        out.extend_from_slice(&self.first_output_leaf_index.to_le_bytes());
        out.extend_from_slice(&self.output_tree);
        out.push(0); // relay_fee: None
        write_len(out, self.deposit_withdraws.len())?;
        for record in self.deposit_withdraws {
            out.push(u8::from(record.is_deposit));
            out.extend_from_slice(&record.amount.to_le_bytes());
            write_option_hash(out, &record.asset);
        }
        Ok(())
    }
}

fn slot_len(slot: &ProoflessOutputSlot) -> Result<usize, EventLengthOverflow> {
    // view_tag, utxo_hash, then the `data` byte vector wrapping the plaintext
    // encoding: its own length prefix, the enum and scheme tags, the inner
    // length prefix, and the output itself.
    let output_len = proofless_output_len(&slot.output)?;
    let mut len = add(64, LEN_PREFIX)?;
    len = add(len, PLAINTEXT_TAGS)?;
    len = add(len, LEN_PREFIX)?;
    add(len, output_len)
}

fn proofless_output_len(output: &ProoflessOutput) -> Result<usize, EventLengthOverflow> {
    let mut len = 32 + 31 + 32 + 8; // owner, blinding, asset, amount
    len = add(len, option_hash_len(&output.data_hash))?;
    len = add(len, option_bytes_len(&output.utxo_data)?)?;
    len = add(len, option_hash_len(&output.zone_program_id))?;
    len = add(len, option_hash_len(&output.zone_data_hash))?;
    len = add(len, option_bytes_len(&output.zone_data)?)?;
    add(len, option_bytes_len(&output.memo)?)
}

fn deposit_withdraw_len(record: &DepositWithdraw) -> usize {
    1 + 8 + option_hash_len(&record.asset)
}

fn option_hash_len(value: &Option<[u8; 32]>) -> usize {
    match value {
        Some(_) => OPTION_TAG + 32,
        None => OPTION_TAG,
    }
}

fn option_bytes_len(value: &Option<Vec<u8>>) -> Result<usize, EventLengthOverflow> {
    match value {
        Some(bytes) => add(OPTION_TAG + LEN_PREFIX, bytes.len()),
        None => Ok(OPTION_TAG),
    }
}

fn write_proofless_output(
    out: &mut Vec<u8>,
    output: &ProoflessOutput,
) -> Result<(), EventLengthOverflow> {
    out.extend_from_slice(&output.owner);
    out.extend_from_slice(&output.blinding);
    out.extend_from_slice(&output.asset);
    out.extend_from_slice(&output.amount.to_le_bytes());
    write_option_hash(out, &output.data_hash);
    write_option_bytes(out, &output.utxo_data)?;
    write_option_hash(out, &output.zone_program_id);
    write_option_hash(out, &output.zone_data_hash);
    write_option_bytes(out, &output.zone_data)?;
    write_option_bytes(out, &output.memo)
}

fn write_option_hash(out: &mut Vec<u8>, value: &Option<[u8; 32]>) {
    match value {
        Some(hash) => {
            out.push(1);
            out.extend_from_slice(hash);
        }
        None => out.push(0),
    }
}

fn write_option_bytes(
    out: &mut Vec<u8>,
    value: &Option<Vec<u8>>,
) -> Result<(), EventLengthOverflow> {
    match value {
        Some(bytes) => {
            out.push(1);
            write_len(out, bytes.len())?;
            out.extend_from_slice(bytes);
            Ok(())
        }
        None => {
            out.push(0);
            Ok(())
        }
    }
}

fn write_len(out: &mut Vec<u8>, len: usize) -> Result<(), EventLengthOverflow> {
    let len = u32::try_from(len).map_err(|_| EventLengthOverflow)?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn add(left: usize, right: usize) -> Result<usize, EventLengthOverflow> {
    left.checked_add(right).ok_or(EventLengthOverflow)
}
