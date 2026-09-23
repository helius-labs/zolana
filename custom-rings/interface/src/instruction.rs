use core::mem::MaybeUninit;
use wincode::{
    config::ConfigCore,
    containers,
    io::{Reader, Writer},
    len::{FixIntLen, SeqLen},
    ReadError, ReadResult, SchemaRead, SchemaWrite, WriteResult,
};
use zolana_interface::instruction::{instruction_data::transact::TreeContext, TransactIxData};
use zolana_ring_policy::{VelocityRow, ANSWER_SLOTS};

use crate::{ReaderKeyBytes, AUDIT_CIPHERTEXT_LEN, COMPRESSED_P256_KEY_LEN};

pub mod tag {
    pub const CREATE_CONFIG: u8 = 1;
    pub const INIT_SPP_RING_CONFIG: u8 = 2;
    pub const TRANSACT: u8 = 3;
    /// Rejected when verified deposit disclosure is required.
    pub const DEPOSIT: u8 = zolana_interface::instruction::tag::RING_DEPOSIT;
    /// SPP ring merge wire tag.
    pub const MERGE: u8 = zolana_interface::instruction::tag::RING_MERGE_TRANSACT;
    pub const GRANT_READ_ACCESS: u8 = 4;
    pub const REVOKE_READ_ACCESS: u8 = 5;
    pub const SET_AUTHORITY: u8 = 6;
    pub const CREATE_POLICY: u8 = 7;
    pub const CREATE_ENTRY: u8 = 8;
    pub const UPDATE_ENTRY: u8 = 9;
    pub const SET_POLICY_SOURCE: u8 = 10;
    pub const SET_PAUSED: u8 = 11;
    pub const SET_POLICY_RULES: u8 = 12;
    /// Ring-local tags must not collide with the forwarded SPP deposit and merge tags.
    pub const SET_CO_SIGNER: u8 = 28;
    pub const CLEAR_CO_SIGNER: u8 = 21;
    pub const SET_SPEND_WINDOW: u8 = 22;
    pub const CLEAR_SPEND_WINDOW: u8 = 23;
    pub const SET_DELEGATE: u8 = 24;
    /// Tag 3 data over the SPP authority rail, signed by the delegate.
    pub const DELEGATE_TRANSACT: u8 = 25;
    pub const REGISTER_SPEND: u8 = 26;
    pub const CREATE_KEY_REGISTRY_ROOT: u8 = 29;
    pub const REGISTER_KEY: u8 = 30;
    pub const SET_DEPOSIT_AUDIT: u8 = 31;
    pub const AUDITED_DEPOSIT: u8 = 32;
}

/// Account slot indices the processors and the indexer agree on.
pub mod accounts {
    pub const REGISTER_SPEND_PAYER: usize = 2;
    pub const REGISTER_KEY_MEMBER: usize = 0;
    pub const REGISTER_KEY_CONFIG: usize = 1;
    pub const REGISTER_KEY_ROOT: usize = 2;
    pub const CREATE_KEY_REGISTRY_ROOT_ROOT: usize = 3;
}

pub const CREATE_CONFIG_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const READ_ACCESS_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_AUTHORITY_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_PAUSED_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_CO_SIGNER_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_SPEND_WINDOW_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_DELEGATE_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const CREATE_KEY_REGISTRY_ROOT_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const SET_DEPOSIT_AUDIT_COMPUTE_UNIT_LIMIT: u32 = 50_000;
pub const AUDITED_DEPOSIT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// Config-authority change to the direct-deposit disclosure requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetDepositAuditIxData {
    pub required: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateConfigIxData {
    /// Auditor P256 public key in SEC1 compressed form.
    pub auditor_pubkey: [u8; COMPRESSED_P256_KEY_LEN],
    /// One selects a policy ring, zero an audit-only ring.
    pub has_policy: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct ReaderIxData {
    pub reader: ReaderKeyBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetPausedIxData {
    /// 1 pauses the ring on SPP, 0 resumes it, any other value is rejected.
    pub paused: u8,
}

/// Public withdrawal total per mint that requires approval when exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct WithdrawalThreshold {
    pub mint: [u8; 32],
    pub amount: u64,
}

/// Requires co-signing for the selected public operations.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetCoSignerIxData {
    pub signer: [u8; 32],
    /// [`CoSignScope`](crate::CoSignScope) bits.
    pub scope: u8,
    #[wincode(with = "containers::Vec<WithdrawalThreshold, FixIntLen<u8>>")]
    pub thresholds: Vec<WithdrawalThreshold>,
}

/// Public deposit and withdrawal caps for one mint over fixed slot windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetSpendWindowIxData {
    pub mint: [u8; 32],
    pub window_slots: u64,
    pub deposit_cap: u64,
    pub withdrawal_cap: u64,
}

/// Groth16 proof of the custom-ring circuit. The circuit's emulated P256
/// arithmetic adds one BSB22 commitment, so the commitment and its
/// proof-of-knowledge are not optional here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CustomRingProof {
    pub groth16: PlainGroth16Proof,
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

impl CustomRingProof {
    pub const SIZE: usize = 192;
}

/// Compressed Groth16 points without the audited circuits' BSB22 commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct PlainGroth16Proof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct KeyRegistryTransition {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
}

/// Wire format of tag 3, the ring's own proof followed by the SPP content this
/// ring forwards verbatim.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CustomRingTransactIxData {
    pub proof: CustomRingProof,
    /// One per policy tree account in order, empty on an audit-only ring.
    #[wincode(with = "containers::Vec<TreeContext, FixIntLen<u8>>")]
    pub policy_trees: Vec<TreeContext>,
    /// Zero unless the ring escrows nullifier keys.
    pub key_registry_root_index: u8,
    /// Proof-bound approval demand, zero when member amount controls do not apply.
    pub approval_required: u8,
    /// Canonical target prefix with a zero suffix in the policy public input.
    #[wincode(with = "CompactRevocationTargets")]
    pub revocation_targets: [[u8; 32]; ANSWER_SLOTS],
    /// Per fact slot, the policy tree its revocation target lives in, zero for an empty slot.
    pub revocation_tree_indexes: [u8; ANSWER_SLOTS],
    pub transact: TransactIxData,
}

struct CompactRevocationTargets;

unsafe impl<'de, C: ConfigCore> SchemaRead<'de, C> for CompactRevocationTargets {
    type Dst = [[u8; 32]; ANSWER_SLOTS];

    fn read(mut reader: impl Reader<'de>, dst: &mut MaybeUninit<Self::Dst>) -> ReadResult<()> {
        let len = <FixIntLen<u8> as SeqLen<C>>::read(reader.by_ref())?;
        if len > ANSWER_SLOTS {
            return Err(ReadError::InvalidValue("too many revocation targets"));
        }
        let mut targets = [[0u8; 32]; ANSWER_SLOTS];
        for target in targets.iter_mut().take(len) {
            *target = <[u8; 32] as SchemaRead<'de, C>>::get(reader.by_ref())?;
        }
        if len != 0 && targets[len - 1] == [0u8; 32] {
            return Err(ReadError::InvalidValue("noncanonical revocation targets"));
        }
        dst.write(targets);
        Ok(())
    }
}

unsafe impl<C: ConfigCore> SchemaWrite<C> for CompactRevocationTargets {
    type Src = [[u8; 32]; ANSWER_SLOTS];

    fn size_of(src: &Self::Src) -> WriteResult<usize> {
        let len = revocation_target_prefix_len(src);
        Ok(1 + len * 32)
    }

    fn write(mut writer: impl Writer, src: &Self::Src) -> WriteResult<()> {
        let len = revocation_target_prefix_len(src);
        <FixIntLen<u8> as SeqLen<C>>::write(writer.by_ref(), len)?;
        for target in &src[..len] {
            <[u8; 32] as SchemaWrite<C>>::write(writer.by_ref(), target)?;
        }
        Ok(())
    }
}

fn revocation_target_prefix_len(targets: &[[u8; 32]; ANSWER_SLOTS]) -> usize {
    targets
        .iter()
        .rposition(|target| *target != [0u8; 32])
        .map_or(0, |index| index + 1)
}

/// Covers one v2 hash pin plus up to eight curator config loads.
pub const CREATE_POLICY_COMPUTE_UNIT_LIMIT: u32 = 150_000;
pub const SET_POLICY_RULES_COMPUTE_UNIT_LIMIT: u32 = 150_000;
/// Entry mutations CPI a full SPP transact with its proof verification.
pub const ENTRY_MUTATION_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// `source` 0 is the ring's own entries, `1 + i` the `i`-th trailing curator
/// policy config account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SourceSpec {
    pub list_id: u8,
    pub source: u8,
}

/// Private outflow cap and per-transfer approval threshold for one asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct VelocityRowIxData {
    pub asset: [u8; 32],
    pub cap: u64,
    pub cosign_above: u64,
}

impl From<&VelocityRowIxData> for VelocityRow {
    fn from(row: &VelocityRowIxData) -> Self {
        Self {
            asset: row.asset,
            cap: row.cap,
            cosign_above: row.cosign_above,
        }
    }
}

impl From<&VelocityRow> for VelocityRowIxData {
    fn from(row: &VelocityRow) -> Self {
        Self {
            asset: row.asset,
            cap: row.cap,
            cosign_above: row.cosign_above,
        }
    }
}

/// Policy parameters must reproduce the configured policy hash.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct PolicyTableIxData {
    #[wincode(with = "containers::Vec<SourceSpec, FixIntLen<u8>>")]
    pub sources: Vec<SourceSpec>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub rules: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub inline_assets: Vec<[u8; 32]>,
    #[wincode(with = "containers::Vec<u64, FixIntLen<u8>>")]
    pub inline_limits: Vec<u64>,
    pub window_slots: u64,
    #[wincode(with = "containers::Vec<VelocityRowIxData, FixIntLen<u8>>")]
    pub velocity: Vec<VelocityRowIxData>,
}

pub const REGISTER_SPEND_COMPUTE_UNIT_LIMIT: u32 = ENTRY_MUTATION_COMPUTE_UNIT_LIMIT;

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RegisterSpendIxData {
    /// The SPP output blinding, the proof fails unless it is the derived one.
    pub blinding: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: zolana_interface::instruction::instruction_data::transact::TransactProof,
}

/// One BSB22 verify over the audited encryption of a member's nullifier key.
pub const REGISTER_KEY_COMPUTE_UNIT_LIMIT: u32 = ENTRY_MUTATION_COMPUTE_UNIT_LIMIT;

/// Proven enrollment of a member's auditor-encrypted nullifier key in the
/// registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RegisterKeyIxData {
    pub proof: CustomRingProof,
    pub registry_old_root: [u8; 32],
    pub registry_new_root: [u8; 32],
    pub registry_next_index: u64,
    /// The member's nullifier public key, bound by the proof to the ciphertext.
    pub nullifier_pk: [u8; 32],
    /// SEC1-compressed ephemeral key the auditor rederives the shared secret from.
    pub eph_pk: [u8; COMPRESSED_P256_KEY_LEN],
    /// AES-256-CTR ciphertext of the nullifier secret, sealed to the auditor.
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

/// One hash over the stored rows plus one curator verification.
pub const SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT: u32 = 150_000;

/// `source` 0 is the ring's own entries, 1 the single trailing curator policy
/// config account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetPolicySourceIxData {
    pub list_id: u8,
    pub source: u8,
}

/// A member-written list requires the payer's Solana address to derive to `member`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateEntryIxData {
    pub list_id: u8,
    pub member: [u8; 32],
    pub state: u8,
    pub content_hash: [u8; 32],
    /// The SPP output blinding, the proof fails unless it is the derived one.
    pub blinding: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: zolana_interface::instruction::instruction_data::transact::TransactProof,
}

/// The spent fields reconstruct the live version, a wrong reconstruction is a
/// leaf the SPP proof cannot include.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UpdateEntryIxData {
    pub list_id: u8,
    pub member: [u8; 32],
    pub spent_state: u8,
    pub spent_content_hash: [u8; 32],
    pub spent_version: u64,
    pub spent_blinding: [u8; 32],
    pub state: u8,
    pub content_hash: [u8; 32],
    pub blinding: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: zolana_interface::instruction::instruction_data::transact::TransactProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
    struct TargetWire {
        #[wincode(with = "CompactRevocationTargets")]
        targets: [[u8; 32]; ANSWER_SLOTS],
    }

    #[test]
    fn revocation_target_wire_preserves_slots_and_omits_the_zero_suffix() {
        let mut targets = [[0u8; 32]; ANSWER_SLOTS];
        targets[0] = [1u8; 32];
        targets[2] = [3u8; 32];
        let encoded = wincode::serialize(&TargetWire { targets }).expect("serialize targets");
        assert_eq!(encoded.len(), 1 + 3 * 32);
        assert_eq!(encoded[0], 3);
        assert_eq!(
            wincode::deserialize_exact::<TargetWire>(&encoded).expect("deserialize targets"),
            TargetWire { targets }
        );
    }

    #[test]
    fn revocation_target_wire_rejects_noncanonical_or_overlong_prefixes() {
        let trailing_zero = [vec![1], vec![0; 32]].concat();
        assert!(wincode::deserialize_exact::<TargetWire>(&trailing_zero).is_err());

        let overlong = [
            vec![(ANSWER_SLOTS + 1) as u8],
            vec![1; (ANSWER_SLOTS + 1) * 32],
        ]
        .concat();
        assert!(wincode::deserialize_exact::<TargetWire>(&overlong).is_err());
    }
}
