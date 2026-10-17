use bytemuck::{Pod, Zeroable};
use thiserror::Error;

pub const MAX_RING_DEPOSIT_AUDIT_SLOTS: usize = 8;
/// One opening is `owner_hash || blinding || owner_key`. The owner key is the
/// Ed25519 key of an anonymous ring deposit and zero otherwise.
pub const RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN: usize = 96;
pub const RING_DEPOSIT_AUDIT_OWNER_KEY_OFFSET: usize = 64;
pub const RING_DEPOSIT_AUDIT_PREFIX_LEN: usize = core::mem::size_of::<CapsuleHeader>();
pub const RING_DEPOSIT_AUDIT_INFO: &[u8; 10] = b"CRING/dep1";

const MAGIC: &[u8; 8] = b"CRDEP001";

/// The auditor's half of an audited deposit output, ahead of the recipient ciphertext.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct CapsuleHeader {
    magic: [u8; 8],
    slot_index: u8,
    eph_pk: [u8; 33],
    ciphertext: [u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDepositAuditCapsule<'a> {
    pub slot_index: u8,
    pub eph_pk: &'a [u8; 33],
    pub ciphertext: &'a [u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
    pub recipient_ciphertext: &'a [u8],
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RingDepositAuditError {
    #[error("ring deposit audit capsule is truncated")]
    Truncated,
    #[error("ring deposit audit slot exceeds the batch limit")]
    InvalidSlot,
}

impl<'a> RingDepositAuditCapsule<'a> {
    /// `None` for an output without the capsule magic.
    pub fn parse(bytes: &'a [u8]) -> Result<Option<Self>, RingDepositAuditError> {
        if !bytes.starts_with(MAGIC) {
            return Ok(None);
        }
        let (header, recipient_ciphertext) = bytes
            .split_at_checked(RING_DEPOSIT_AUDIT_PREFIX_LEN)
            .ok_or(RingDepositAuditError::Truncated)?;
        let header: &CapsuleHeader = bytemuck::from_bytes(header);
        if usize::from(header.slot_index) >= MAX_RING_DEPOSIT_AUDIT_SLOTS {
            return Err(RingDepositAuditError::InvalidSlot);
        }
        Ok(Some(Self {
            slot_index: header.slot_index,
            eph_pk: &header.eph_pk,
            ciphertext: &header.ciphertext,
            recipient_ciphertext,
        }))
    }

    pub fn encode(self) -> Vec<u8> {
        let header = CapsuleHeader {
            magic: *MAGIC,
            slot_index: self.slot_index,
            eph_pk: *self.eph_pk,
            ciphertext: *self.ciphertext,
        };
        [bytemuck::bytes_of(&header), self.recipient_ciphertext].concat()
    }
}

const _: () = assert!(RING_DEPOSIT_AUDIT_PREFIX_LEN == 138);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_preserves_recipient_bytes_and_binds_the_slot() {
        let raw = [17; 73];
        assert_eq!(RingDepositAuditCapsule::parse(&raw), Ok(None));
        let frame = RingDepositAuditCapsule {
            slot_index: 7,
            eph_pk: &[2; 33],
            ciphertext: &[3; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
            recipient_ciphertext: &raw,
        }
        .encode();
        assert_eq!(frame.len(), RING_DEPOSIT_AUDIT_PREFIX_LEN + raw.len());
        let capsule = RingDepositAuditCapsule::parse(&frame).unwrap().unwrap();
        assert_eq!(capsule.slot_index, 7);
        assert_eq!(capsule.eph_pk, &[2; 33]);
        assert_eq!(capsule.ciphertext, &[3; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]);
        assert_eq!(capsule.recipient_ciphertext, raw);
        for length in MAGIC.len()..RING_DEPOSIT_AUDIT_PREFIX_LEN {
            assert_eq!(
                RingDepositAuditCapsule::parse(&frame[..length]),
                Err(RingDepositAuditError::Truncated),
            );
        }
        let mut invalid = frame;
        invalid[8] = MAX_RING_DEPOSIT_AUDIT_SLOTS as u8;
        assert_eq!(
            RingDepositAuditCapsule::parse(&invalid),
            Err(RingDepositAuditError::InvalidSlot)
        );
    }
}
