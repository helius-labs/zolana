//! Ring-proof witness builder and prover glue (gated under the `prover` feature).
//!
//! Mirrors the squads ring circuit
//! `rings/squads/prover/circuits/ring/{circuit.go,view_key.go,sender.go,
//! recipient.go,proposal.go}` and the shared gadgets in
//! `rings/squads/prover/circuits/ringutils/{poseidon_kdf.go,transaction.go,x25519.go}`.
//!
//! The ring proof shares `private_tx_hash` with the SPP proof, so every UTXO
//! commitment, the output blindings and the private tx blinding follow SPP's
//! canonical definitions (`zolana_transaction`): the change and recipient
//! blindings are SPP output blindings derived from a `blinding_seed` that the
//! sender's shared viewing secret determines, which lets the holder of that
//! secret (the owner or the auditor) rebuild the change output.
//!
//! The prover assigns every field verbatim and the circuit asserts that the
//! supplied `PublicInputHash` equals the chain it recomputes, so the host
//! computation here must match the circuit exactly or proving fails outright.

use squads_prover::{
    ProposalProofInput, RecipientProofInput, RingProofInputs, RingUtxoProofInput, SenderProofInput,
};
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::{X25519Keypair, X25519Pubkey};
use zolana_transaction::{
    derive_output_blinding_seed, derive_private_tx_blinding, instructions::transact::PrivateTxHash,
    utxo::derive_transact_output_blinding,
};

use crate::{
    encrypted_utxo::{encrypt_recipient_ciphertext, encrypt_sender_ciphertext},
    prover::{
        error::SquadsProverError,
        shared_viewing_key::{ciphertext_hash, hash_chain, pack33},
    },
};

use squads_prover::RING_SUPPORTED_SHAPES;

/// SPP slot domains (`spp_transaction/shared/transaction.go`).
pub const DUMMY_DOMAIN: u64 = 1;
pub const UTXO_DOMAIN: u64 = 3;

/// Output slot of the sender change and of a transfer's recipient output.
pub const SENDER_OUTPUT_INDEX: u32 = 0;
pub const RECIPIENT_OUTPUT_INDEX: u32 = 1;

/// One transaction slot as the ring circuit witnesses it (`ringutils.Utxo`).
/// `owner_key_hash` is the owner's SPP owner identity and, with
/// `nullifier_pubkey`, reconstructs `owner_hash`. All scalar fields are 32-byte
/// big-endian field elements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingUtxo {
    pub domain: u64,
    pub tree_id: u16,
    pub owner_key_hash: [u8; 32],
    pub nullifier_pubkey: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
    pub blinding: [u8; 32],
    pub program_data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub ring_program_id: [u8; 32],
}

impl RingUtxo {
    /// A padding input slot: it contributes 0 to `private_tx_hash`, so only its
    /// zero amount is constrained.
    pub fn dummy(tree_id: u16, blinding: [u8; 32]) -> Self {
        Self {
            domain: DUMMY_DOMAIN,
            tree_id,
            owner_key_hash: [0u8; 32],
            nullifier_pubkey: [0u8; 32],
            asset: [0u8; 32],
            amount: 0,
            blinding,
            program_data_hash: [0u8; 32],
            ring_data_hash: [0u8; 32],
            ring_program_id: [0u8; 32],
        }
    }

    pub fn is_dummy(&self) -> bool {
        self.domain == DUMMY_DOMAIN
    }

    /// `Poseidon(owner_key_hash, nullifier_pubkey)`.
    pub fn owner_hash(&self) -> Result<[u8; 32], SquadsProverError> {
        poseidon(&[&self.owner_key_hash, &self.nullifier_pubkey])
    }

    /// SPP's UTXO hash (`spp_transaction/shared/utxo.go`):
    /// `Poseidon(domain, tree_id, asset, amount, data_hash,
    /// Poseidon(ring_data_hash, ring_program_id), Poseidon(owner_hash, blinding))`.
    pub fn hash(&self) -> Result<[u8; 32], SquadsProverError> {
        let owner_utxo_hash = poseidon(&[&self.owner_hash()?, &self.blinding])?;
        let ring_hash = poseidon(&[&self.ring_data_hash, &self.ring_program_id])?;
        poseidon(&[
            &right_align_u64(self.domain),
            &right_align_u64(u64::from(self.tree_id)),
            &self.asset,
            &right_align_u64(self.amount),
            &self.program_data_hash,
            &ring_hash,
            &owner_utxo_hash,
        ])
    }

    /// The slot's element of its `private_tx_hash` chain: 0 for a dummy.
    fn chain_element(&self) -> Result<[u8; 32], SquadsProverError> {
        if self.is_dummy() {
            Ok([0u8; 32])
        } else {
            self.hash()
        }
    }
}

/// The recipient of a transfer. The prover holds no recipient secret, so only the
/// recipient's public account identity and viewing pubkey are provided.
#[derive(Clone, Debug)]
pub struct RingRecipient {
    pub owner_key_hash: [u8; 32],
    pub nullifier_pubkey: [u8; 32],
    pub viewing_pubkey: X25519Pubkey,
}

/// An optional proposal commitment bound into the proof.
#[derive(Clone, Debug)]
pub struct RingProposal {
    pub amount: [u8; 32],
    pub recipient: [u8; 32],
    pub blinding: [u8; 32],
    pub public_amount: [u8; 32],
}

/// The values the sender's shared viewing secret and the first nullifier
/// determine: the ephemeral transaction viewing key, the SPP `blinding_seed`,
/// and the output blindings derived from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendSecrets {
    /// `tx_viewing_sk`, a BN254 field element also used as raw X25519 secret bytes.
    pub tx_viewing_sk: [u8; 32],
    /// Compressed `tx_viewing_sk · G`.
    pub tx_viewing_pk: [u8; 33],
    /// SPP `blinding_seed = PoseidonKDF(tx_viewing_sk, "blinding")`.
    pub blinding_seed: [u8; 32],
    /// SPP output blinding of the sender change (slot 0).
    pub change_blinding: [u8; 32],
    /// SPP output blinding of a transfer's recipient output (slot 1).
    pub recipient_blinding: [u8; 32],
}

/// Derive [`SpendSecrets`] (sender.go):
///
/// ```text
/// view_root         = PoseidonKDF(viewing_sk)
/// tx_viewing_secret = PoseidonKDF(view_root, "TSPP/tx_viewing")
/// tx_viewing_sk     = PoseidonKDF(tx_viewing_secret, first_nullifier)
/// blinding_seed     = PoseidonKDF(tx_viewing_sk, "blinding")
/// ```
pub fn derive_spend_secrets(
    viewing_secret_key: &X25519Keypair,
    first_nullifier: &[u8; 32],
) -> Result<SpendSecrets, SquadsProverError> {
    let (sk_low, sk_high, _commitment) = viewing_commitment(&secret_bytes(viewing_secret_key))?;
    let view_root = poseidon_kdf(&[&sk_low, &sk_high])?;
    let tx_viewing_secret = poseidon_kdf(&[&view_root, &right_align_label(b"TSPP/tx_viewing")])?;
    let tx_viewing_sk = poseidon_kdf(&[&tx_viewing_secret, first_nullifier])?;
    let blinding_seed = poseidon_kdf(&[&tx_viewing_sk, &right_align_label(b"blinding")])?;

    let output_seed = derive_output_blinding_seed(first_nullifier, &blinding_seed)
        .map_err(|_| SquadsProverError::Poseidon)?;
    let change_blinding =
        derive_transact_output_blinding(first_nullifier, &output_seed, SENDER_OUTPUT_INDEX)
            .map_err(|_| SquadsProverError::Poseidon)?;
    let recipient_blinding =
        derive_transact_output_blinding(first_nullifier, &output_seed, RECIPIENT_OUTPUT_INDEX)
            .map_err(|_| SquadsProverError::Poseidon)?;
    let tx_viewing_pk = *X25519Keypair::from_bytes(&tx_viewing_sk)
        .pubkey()
        .as_bytes();
    Ok(SpendSecrets {
        tx_viewing_sk,
        tx_viewing_pk,
        blinding_seed,
        change_blinding,
        recipient_blinding,
    })
}

/// The squads output ciphertexts of a spend: the sender change (`amount ||
/// asset`, keyed by `tx_viewing_sk`) and, for a transfer, the recipient output
/// (`amount || asset || blinding`, keyed by the ECDH secret with the recipient's
/// viewing key).
pub struct SpendCiphertexts {
    pub sender: Vec<u8>,
    pub recipient: Option<Vec<u8>>,
}

/// Encrypt the change and (transfer only) recipient outputs exactly as the
/// circuit does.
pub fn encrypt_spend_outputs(
    secrets: &SpendSecrets,
    change: &RingUtxo,
    recipient: Option<(&RingRecipient, &RingUtxo)>,
) -> Result<SpendCiphertexts, SquadsProverError> {
    let sender = encrypt_sender_ciphertext(&secrets.tx_viewing_sk, change.amount, &change.asset)
        .map_err(|_| SquadsProverError::Poseidon)?
        .to_vec();
    let recipient = match recipient {
        Some((recipient, output)) => {
            let tx_viewing_sk = X25519Keypair::from_bytes(&secrets.tx_viewing_sk);
            Some(
                encrypt_recipient_ciphertext(
                    &tx_viewing_sk,
                    &recipient.viewing_pubkey,
                    output.amount,
                    &output.asset,
                    &output.blinding,
                )
                .map_err(|_| SquadsProverError::InvalidPubkey)?
                .to_vec(),
            )
        }
        None => None,
    };
    Ok(SpendCiphertexts { sender, recipient })
}

/// Inputs to a ring proof.
pub struct RingWitness {
    /// The sender's shared viewing secret key (a X25519 secret).
    pub viewing_secret_key: X25519Keypair,
    /// The sender's nullifier secret as a 32-byte field element.
    pub nullifier_secret: [u8; 32],
    /// Spent input slots; `inputs[0]` is real and seeds the KDF chain.
    pub inputs: Vec<RingUtxo>,
    /// `outputs[0]` is the sender change; a transfer's `outputs[1]` is the
    /// recipient output.
    pub outputs: Vec<RingUtxo>,
    /// SPP `external_data_hash`, bound separately in the ring public-input chain.
    pub external_data_hash: [u8; 32],
    /// Present iff this is a transfer (2 outputs).
    pub recipient: Option<RingRecipient>,
    /// The proposal commitment (enabled iff `Some`).
    pub proposal: Option<RingProposal>,
    /// The public withdrawn amount (0 for a transfer).
    pub public_amount: [u8; 32],
}

/// The published artefacts and proof of a ring proof.
pub struct RingProofResult {
    /// The 192-byte compressed Groth16 proof (BSB22 layout, commitment included).
    pub proof: [u8; 192],
    /// The public-input hash the circuit constrains and the program recomputes.
    pub public_input_hash: [u8; 32],
    /// The `private_tx_hash` the ring and SPP proofs share.
    pub private_tx_hash: [u8; 32],
    /// `Poseidon(skLow, skHigh)`; equals the sender viewing key account's
    /// `shared_viewing_key_commitment`.
    pub commitment: [u8; 32],
    /// `Poseidon(amount, recipient, blinding, public_amount)`, or 0.
    pub proposal_hash: [u8; 32],
    pub ciphertexts: SpendCiphertexts,
    pub secrets: SpendSecrets,
}

impl RingWitness {
    /// Recompute every circuit value, check the witness is consistent, prove,
    /// and return the proof with its published values.
    pub fn prove(self) -> Result<RingProofResult, SquadsProverError> {
        let computed = self.compute()?;
        let proof = self.proof_inputs(&computed)?.prove()?;
        Ok(RingProofResult {
            proof,
            public_input_hash: computed.public_input_hash,
            private_tx_hash: computed.private_tx_hash,
            commitment: computed.commitment,
            proposal_hash: computed.proposal_hash,
            ciphertexts: computed.ciphertexts,
            secrets: computed.secrets,
        })
    }

    /// The `private_tx_hash` this witness binds, without proving.
    pub fn private_tx_hash(&self) -> Result<[u8; 32], SquadsProverError> {
        Ok(self.compute()?.private_tx_hash)
    }

    fn compute(&self) -> Result<Computed, SquadsProverError> {
        let n_inputs = self.inputs.len();
        let n_outputs = self.outputs.len();
        let shape = (
            u8::try_from(n_inputs)
                .map_err(|_| SquadsProverError::UnsupportedShape(n_inputs, n_outputs))?,
            u8::try_from(n_outputs)
                .map_err(|_| SquadsProverError::UnsupportedShape(n_inputs, n_outputs))?,
        );
        if !RING_SUPPORTED_SHAPES.contains(&shape) {
            return Err(SquadsProverError::UnsupportedShape(n_inputs, n_outputs));
        }
        let has_recipient = n_outputs == 2;
        if has_recipient != self.recipient.is_some() {
            return Err(SquadsProverError::UnsupportedShape(n_inputs, n_outputs));
        }
        let first_input = self
            .inputs
            .first()
            .ok_or(SquadsProverError::UnsupportedShape(n_inputs, n_outputs))?;
        if first_input.is_dummy() {
            return Err(SquadsProverError::DummyFirstInput);
        }
        if self
            .inputs
            .iter()
            .any(|input| input.is_dummy() && input.amount != 0)
            || self.outputs.iter().any(RingUtxo::is_dummy)
        {
            return Err(SquadsProverError::InvalidAmount);
        }
        let change = self
            .outputs
            .first()
            .ok_or(SquadsProverError::UnsupportedShape(n_inputs, n_outputs))?;

        let first_nullifier = poseidon(&[
            &first_input.hash()?,
            &first_input.blinding,
            &self.nullifier_secret,
        ])?;
        let secrets = derive_spend_secrets(&self.viewing_secret_key, &first_nullifier)?;
        if secrets.change_blinding != change.blinding {
            return Err(SquadsProverError::BlindingMismatch);
        }

        let input_hashes: Vec<[u8; 32]> = self
            .inputs
            .iter()
            .map(RingUtxo::chain_element)
            .collect::<Result<_, _>>()?;
        let output_hashes: Vec<[u8; 32]> = self
            .outputs
            .iter()
            .map(RingUtxo::chain_element)
            .collect::<Result<_, _>>()?;
        let private_tx_blinding =
            derive_private_tx_blinding(&first_nullifier, &secrets.blinding_seed)
                .map_err(|_| SquadsProverError::Poseidon)?;
        let private_tx_hash =
            PrivateTxHash::new(&input_hashes, &output_hashes, &private_tx_blinding)
                .hash()
                .map_err(|_| SquadsProverError::Poseidon)?;

        let (_sk_low, _sk_high, commitment) =
            viewing_commitment(&secret_bytes(&self.viewing_secret_key))?;
        let recipient = match (&self.recipient, self.outputs.get(1)) {
            (Some(recipient), Some(output)) => Some((recipient, output)),
            (None, None) => None,
            _ => return Err(SquadsProverError::UnsupportedShape(n_inputs, n_outputs)),
        };
        let ciphertexts = encrypt_spend_outputs(&secrets, change, recipient)?;

        let mut chain: Vec<[u8; 32]> = vec![
            private_tx_hash,
            self.external_data_hash,
            self.public_amount,
            poseidon(&[
                &change.owner_key_hash,
                &commitment,
                &change.nullifier_pubkey,
            ])?,
            ciphertext_hash(&ciphertexts.sender)?,
        ];
        if let (Some((recipient, _)), Some(recipient_ciphertext)) =
            (recipient, ciphertexts.recipient.as_ref())
        {
            let (tx_pk_lo, tx_pk_hi) = pack33(&secrets.tx_viewing_pk);
            let (vpk_lo, vpk_hi) = pack33(recipient.viewing_pubkey.as_bytes());
            chain.push(tx_pk_lo);
            chain.push(tx_pk_hi);
            chain.push(poseidon(&[
                &recipient.owner_key_hash,
                &vpk_lo,
                &vpk_hi,
                &recipient.nullifier_pubkey,
            ])?);
            chain.push(ciphertext_hash(recipient_ciphertext)?);
        }
        let proposal_hash = match &self.proposal {
            Some(p) => poseidon(&[&p.amount, &p.recipient, &p.blinding, &p.public_amount])?,
            None => [0u8; 32],
        };
        chain.push(proposal_hash);
        let public_input_hash = hash_chain(&chain)?;

        Ok(Computed {
            public_input_hash,
            private_tx_hash,
            commitment,
            proposal_hash,
            ciphertexts,
            secrets,
        })
    }

    fn proof_inputs(&self, computed: &Computed) -> Result<RingProofInputs, SquadsProverError> {
        let inputs = self
            .inputs
            .iter()
            .map(utxo_proof_input)
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = self
            .outputs
            .iter()
            .map(utxo_proof_input)
            .collect::<Result<Vec<_>, _>>()?;
        let change = self
            .outputs
            .first()
            .ok_or(SquadsProverError::UnsupportedShape(self.inputs.len(), 0))?;
        let sender = SenderProofInput {
            owner: change.owner_key_hash,
            shared_viewing_secret_key_commitment: computed.commitment,
            nullifier_pubkey: change.nullifier_pubkey,
            nullifier_secret: self.nullifier_secret,
            shared_viewing_secret_key: secret_bytes(&self.viewing_secret_key),
        };
        let recipient = match &self.recipient {
            Some(r) => RecipientProofInput {
                owner: r.owner_key_hash,
                nullifier_pubkey: r.nullifier_pubkey,
                viewing_pubkey: *r.viewing_pubkey.as_bytes(),
            },
            None => RecipientProofInput::default(),
        };
        let proposal = match &self.proposal {
            Some(p) => ProposalProofInput {
                amount: p.amount,
                recipient: p.recipient,
                blinding: p.blinding,
                public_amount: p.public_amount,
            },
            None => ProposalProofInput::default(),
        };
        Ok(RingProofInputs {
            inputs,
            outputs,
            external_data_hash: self.external_data_hash,
            sender,
            recipient,
            proposal,
            enable_proposal_hash: self.proposal.is_some(),
            public_amount: self.public_amount,
            public_input_hash: computed.public_input_hash,
        })
    }
}

struct Computed {
    public_input_hash: [u8; 32],
    private_tx_hash: [u8; 32],
    commitment: [u8; 32],
    proposal_hash: [u8; 32],
    ciphertexts: SpendCiphertexts,
    secrets: SpendSecrets,
}

/// Decrypt a 40-byte sender-change ciphertext. The change output of a spend is
/// keyed by `tx_viewing_sk`, which the shared viewing secret and the spend's
/// first published nullifier determine, so the holder of the viewing secret
/// recovers the change amount, asset field element and blinding from the event
/// alone. A wrong nullifier yields garbage; callers validate the asset.
pub fn decrypt_sender_change(
    viewing_secret_key: &X25519Keypair,
    first_nullifier: &[u8; 32],
    ciphertext: &[u8],
) -> Result<(u64, [u8; 32], [u8; 32]), SquadsProverError> {
    let ciphertext: &[u8; crate::encrypted_utxo::SENDER_CIPHERTEXT_LEN] = ciphertext
        .try_into()
        .map_err(|_| SquadsProverError::InvalidProofEncoding)?;
    let secrets = derive_spend_secrets(viewing_secret_key, first_nullifier)?;
    let (amount, asset) =
        crate::encrypted_utxo::decrypt_sender_ciphertext(&secrets.tx_viewing_sk, ciphertext)
            .map_err(|_| SquadsProverError::InvalidProofEncoding)?;
    Ok((amount, asset, secrets.change_blinding))
}

// ---- field-element helpers ------------------------------------------------

/// A `u64` zero-padded (right-aligned big-endian) into a field element.
pub(crate) fn right_align_u64(x: u64) -> [u8; 32] {
    let mut fe = [0u8; 32];
    fe[24..32].copy_from_slice(&x.to_be_bytes());
    fe
}

/// A short ASCII label right-aligned into a field element, matching Go's
/// `new(big.Int).SetBytes([]byte(label))`.
fn right_align_label(label: &[u8]) -> [u8; 32] {
    let mut fe = [0u8; 32];
    let start = 32 - label.len();
    fe[start..].copy_from_slice(label);
    fe
}

fn poseidon(inputs: &[&[u8]]) -> Result<[u8; 32], SquadsProverError> {
    Poseidon::hashv(inputs).map_err(|_| SquadsProverError::Poseidon)
}

/// One keyed KDF step: `Poseidon("TSPP/kdf", inputs...)` (poseidon_kdf.go).
fn poseidon_kdf(inputs: &[&[u8]]) -> Result<[u8; 32], SquadsProverError> {
    let sep = right_align_label(b"TSPP/kdf");
    let mut all: Vec<&[u8]> = Vec::with_capacity(inputs.len() + 1);
    all.push(&sep);
    all.extend_from_slice(inputs);
    poseidon(&all)
}

/// `(sk_low, sk_high, commitment)` of a viewing secret.
type ViewingCommitment = ([u8; 32], [u8; 32], [u8; 32]);

/// `Poseidon(skLow, skHigh)` viewing-key commitment (view_key.go), where the
/// limbs are the low / high 128 bits of the 32-byte raw secret.
fn viewing_commitment(viewing_sk_be: &[u8; 32]) -> Result<ViewingCommitment, SquadsProverError> {
    let (high_bytes, low_bytes) = viewing_sk_be.split_at(16);
    let mut sk_low = [0u8; 32];
    let mut sk_high = [0u8; 32];
    sk_low[16..].copy_from_slice(low_bytes);
    sk_high[16..].copy_from_slice(high_bytes);
    let commitment = poseidon(&[&sk_low, &sk_high])?;
    Ok((sk_low, sk_high, commitment))
}

fn secret_bytes(secret: &X25519Keypair) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(secret.secret_bytes().as_slice());
    out
}

fn utxo_proof_input(u: &RingUtxo) -> Result<RingUtxoProofInput, SquadsProverError> {
    Ok(RingUtxoProofInput {
        domain: right_align_u64(u.domain),
        tree_id: right_align_u64(u64::from(u.tree_id)),
        owner_hash: u.owner_hash()?,
        asset: u.asset,
        amount: right_align_u64(u.amount),
        blinding: u.blinding,
        program_data_hash: u.program_data_hash,
        ring_data_hash: u.ring_data_hash,
        ring_program_id: u.ring_program_id,
    })
}
