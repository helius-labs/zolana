use core::mem::MaybeUninit;

use bytemuck::{Pod, Zeroable};
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

/// Account slot indices the processors and the indexer agree on.
pub mod accounts {
    pub const REGISTER_SPEND_PAYER: usize = 2;
    pub const REGISTER_KEY_MEMBER: usize = 0;
    pub const REGISTER_KEY_CONFIG: usize = 1;
    pub const REGISTER_KEY_ROOT: usize = 2;
    pub const CREATE_KEY_REGISTRY_ROOT_ROOT: usize = 3;
}

macro_rules! instruction_tags {
    ($($(#[$doc:meta])* $variant:ident = $tag:ident: $value:expr => $units:expr,)*) => {
        pub mod tag {
            $($(#[$doc])* pub const $tag: u8 = $value;)*
        }

        /// The first byte of the instruction data.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum InstructionTag {
            $($variant = tag::$tag,)*
        }

        impl TryFrom<u8> for InstructionTag {
            type Error = ();

            fn try_from(value: u8) -> Result<Self, ()> {
                match value {
                    $(tag::$tag => Ok(Self::$variant),)*
                    _ => Err(()),
                }
            }
        }

        /// The compute budget one instruction of `tag` declares.
        pub const fn compute_unit_limit(tag: InstructionTag) -> u32 {
            match tag {
                $(InstructionTag::$variant => $units,)*
            }
        }
    };
}

const ACCOUNT_UNITS: u32 = 50_000;
/// One policy hash plus up to eight curator config loads.
const POLICY_UNITS: u32 = 150_000;
/// A ring proof, most also CPI into SPP and its own proof.
const PROOF_UNITS: u32 = 1_400_000;

instruction_tags! {
    CreateConfig = CREATE_CONFIG: 1 => ACCOUNT_UNITS,
    InitSppRingConfig = INIT_SPP_RING_CONFIG: 2 => ACCOUNT_UNITS,
    Transact = TRANSACT: 3 => PROOF_UNITS,
    /// Rejected when verified deposit disclosure is required.
    Deposit = DEPOSIT: zolana_interface::instruction::tag::RING_DEPOSIT => 200_000,
    Merge = MERGE: zolana_interface::instruction::tag::RING_MERGE_TRANSACT => PROOF_UNITS,
    GrantReadAccess = GRANT_READ_ACCESS: 4 => ACCOUNT_UNITS,
    RevokeReadAccess = REVOKE_READ_ACCESS: 5 => ACCOUNT_UNITS,
    SetAuthority = SET_AUTHORITY: 6 => ACCOUNT_UNITS,
    CreatePolicy = CREATE_POLICY: 7 => POLICY_UNITS,
    CreateEntry = CREATE_ENTRY: 8 => PROOF_UNITS,
    UpdateEntry = UPDATE_ENTRY: 9 => PROOF_UNITS,
    SetPolicySource = SET_POLICY_SOURCE: 10 => POLICY_UNITS,
    SetPaused = SET_PAUSED: 11 => ACCOUNT_UNITS,
    SetPolicyRules = SET_POLICY_RULES: 12 => POLICY_UNITS,
    /// Ring-local tags must not collide with the forwarded SPP deposit and merge tags.
    SetCoSigner = SET_CO_SIGNER: 27 => ACCOUNT_UNITS,
    ClearCoSigner = CLEAR_CO_SIGNER: 21 => ACCOUNT_UNITS,
    SetSpendWindow = SET_SPEND_WINDOW: 22 => ACCOUNT_UNITS,
    ClearSpendWindow = CLEAR_SPEND_WINDOW: 23 => ACCOUNT_UNITS,
    SetDelegate = SET_DELEGATE: 24 => ACCOUNT_UNITS,
    /// Tag 3 data over the SPP authority rail, signed by the delegate.
    DelegateTransact = DELEGATE_TRANSACT: 25 => PROOF_UNITS,
    RegisterSpend = REGISTER_SPEND: 26 => PROOF_UNITS,
    CreateKeyRegistryRoot = CREATE_KEY_REGISTRY_ROOT: 28 => ACCOUNT_UNITS,
    RegisterKey = REGISTER_KEY: 29 => PROOF_UNITS,
    SetDepositAudit = SET_DEPOSIT_AUDIT: 30 => ACCOUNT_UNITS,
    AuditedDeposit = AUDITED_DEPOSIT: 31 => PROOF_UNITS,
}

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

/// Emulated P256 adds one BSB22 commitment, its point and proof of knowledge are mandatory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable, SchemaRead, SchemaWrite)]
#[repr(C)]
pub struct CustomRingProof {
    pub groth16: PlainGroth16Proof,
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

impl CustomRingProof {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

const _: () = assert!(CustomRingProof::SIZE == 192);

/// Compressed Groth16 points without the audited circuits' BSB22 commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable, SchemaRead, SchemaWrite)]
#[repr(C)]
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

/// Tag 3, the ring's own proof followed by the SPP content it forwards verbatim.
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

/// `source` 0 is the ring's own entries, `1 + i` the `i`-th trailing curator policy config.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SourceSpec {
    pub list_id: u8,
    pub source: u8,
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
    #[wincode(with = "containers::Vec<VelocityRow, FixIntLen<u8>>")]
    pub velocity: Vec<VelocityRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct RegisterSpendIxData {
    /// The SPP output blinding, the proof fails unless it is the derived one.
    pub blinding: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: zolana_interface::instruction::instruction_data::transact::TransactProof,
}

/// Proven enrollment of a member's auditor-encrypted nullifier key in the registry.
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

/// `source` 0 is the ring's own entries, 1 the single trailing curator policy config.
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

/// The spent fields rebuild the live version, a wrong one is a leaf no SPP proof includes.
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
