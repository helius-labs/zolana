pub const MAX_RING_DEPOSIT_AUDIT_SLOTS: usize = 8;
pub const RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN: usize = 64;
pub const RING_DEPOSIT_AUDIT_PREFIX_LEN: usize = 106;
pub const RING_DEPOSIT_AUDIT_INFO: &[u8; 10] = b"CRING/dep1";

const MAGIC: &[u8; 8] = b"CRDEP001";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDepositAuditCapsule<'a> {
    pub slot_index: u8,
    pub eph_pk: &'a [u8; 33],
    pub ciphertext: &'a [u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
    pub recipient_ciphertext: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingDepositAuditError {
    Truncated,
    InvalidSlot,
}

impl core::fmt::Display for RingDepositAuditError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "ring deposit audit capsule is truncated",
            Self::InvalidSlot => "ring deposit audit slot exceeds the batch limit",
        })
    }
}

impl std::error::Error for RingDepositAuditError {}

impl<'a> RingDepositAuditCapsule<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Option<Self>, RingDepositAuditError> {
        if !bytes.starts_with(MAGIC) {
            return Ok(None);
        }
        let (header, recipient_ciphertext) = bytes
            .split_at_checked(RING_DEPOSIT_AUDIT_PREFIX_LEN)
            .ok_or(RingDepositAuditError::Truncated)?;
        let slot_index = header[8];
        if usize::from(slot_index) >= MAX_RING_DEPOSIT_AUDIT_SLOTS {
            return Err(RingDepositAuditError::InvalidSlot);
        }
        Ok(Some(Self {
            slot_index,
            eph_pk: header[9..42]
                .try_into()
                .map_err(|_| RingDepositAuditError::Truncated)?,
            ciphertext: header[42..106]
                .try_into()
                .map_err(|_| RingDepositAuditError::Truncated)?,
            recipient_ciphertext,
        }))
    }

    pub fn encode(self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(RING_DEPOSIT_AUDIT_PREFIX_LEN + self.recipient_ciphertext.len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(self.slot_index);
        bytes.extend_from_slice(self.eph_pk);
        bytes.extend_from_slice(self.ciphertext);
        bytes.extend_from_slice(self.recipient_ciphertext);
        bytes
    }
}

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
            ciphertext: &[3; 64],
            recipient_ciphertext: &raw,
        }
        .encode();
        assert_eq!(frame.len(), RING_DEPOSIT_AUDIT_PREFIX_LEN + raw.len());
        let capsule = RingDepositAuditCapsule::parse(&frame).unwrap().unwrap();
        assert_eq!(capsule.slot_index, 7);
        assert_eq!(capsule.eph_pk, &[2; 33]);
        assert_eq!(capsule.ciphertext, &[3; 64]);
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
