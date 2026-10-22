use custom_ring_interface::{
    CustomRingError, ReaderKeyBytes, RingAccount, READER_KEY_ED25519, READER_KEY_P256,
    VIEWING_PUBKEY_TAG,
};
use pinocchio::{AccountView, ProgramResult};
use solana_curve25519::{
    edwards::{add_edwards, multiply_edwards, validate_edwards, PodEdwardsPoint},
    scalar::PodScalar,
};
use zolana_hasher::primitives::is_canonical_x25519_public_key;

pub(crate) struct Init<'a, T>(pub &'a T);

impl<T: RingAccount> Init<'_, T> {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account.try_borrow_mut().map_err(|_| T::EXISTS)?;
        if data.len() != T::SIZE {
            return Err(T::ADDRESS.into());
        }
        // A nonzero first byte is a live discriminator, never overwrite it.
        if data[0] != 0 {
            return Err(T::EXISTS.into());
        }
        data.copy_from_slice(bytemuck::bytes_of(self.0));
        Ok(())
    }
}

/// The canonical low-order u coordinates on the curve and its twist.
const LOW_ORDER_U: [[u8; 32]; 5] = [
    [0; 32],
    {
        let mut u = [0; 32];
        u[0] = 1;
        u
    },
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    {
        let mut u = [0xff; 32];
        u[0] = 0xec;
        u[31] = 0x7f;
        u
    },
];

/// Accepts a canonical auditor key only when clamped ECDH can be contributory.
/// Low-order peers yield zero DH for every secret and cannot satisfy the proof.
pub(crate) fn is_x25519_key(key: &[u8; 33]) -> bool {
    key[0] == VIEWING_PUBKEY_TAG
        && <&[u8; 32]>::try_from(&key[1..]).is_ok_and(is_canonical_x25519_public_key)
        && !LOW_ORDER_U.iter().any(|u| key[1..] == *u)
}

/// Curve membership is the SDK's job, an off-curve key only fails its own ring closed.
fn is_p256_key(key: &[u8; 33]) -> bool {
    matches!(key[0], 0x02 | 0x03)
}

pub(crate) fn check_reader_key(key: &ReaderKeyBytes) -> Result<(), CustomRingError> {
    let valid = match key[0] {
        READER_KEY_P256 => <&[u8; 33]>::try_from(&key[1..]).is_ok_and(is_p256_key),
        READER_KEY_ED25519 => {
            key[33] == 0 && <[u8; 32]>::try_from(&key[1..33]).is_ok_and(is_signing_ed25519_key)
        }
        _ => false,
    };
    valid.then_some(()).ok_or(CustomRingError::InvalidReaderKey)
}

fn is_signing_ed25519_key(body: [u8; 32]) -> bool {
    const FIELD_MODULUS: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    const SUBGROUP_ORDER_MINUS_ONE: PodScalar = PodScalar([
        0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]);
    const IDENTITY: PodEdwardsPoint = PodEdwardsPoint([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);

    let mut y = body;
    y[31] &= 0x7f;
    let point = PodEdwardsPoint(body);
    y.iter().rev().cmp(FIELD_MODULUS.iter().rev()).is_lt()
        && validate_edwards(&point)
        && y != IDENTITY.0
        && multiply_edwards(&SUBGROUP_ORDER_MINUS_ONE, &point)
            .and_then(|multiple| add_edwards(&multiple, &point))
            .is_some_and(|point| point == IDENTITY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auditor_keys_must_be_tagged_canonical_and_of_large_order() {
        let key = |u: [u8; 32]| {
            let mut key = [VIEWING_PUBKEY_TAG; 33];
            key[1..].copy_from_slice(&u);
            key
        };
        let secret = x25519_dalek::StaticSecret::from([9u8; 32]);
        let public = *x25519_dalek::PublicKey::from(&secret).as_bytes();
        assert!(is_x25519_key(&key(public)));
        let mut sec1 = key(public);
        sec1[0] = 2;
        assert!(!is_x25519_key(&sec1));
        let mut modulus = [0xff; 32];
        modulus[0] = 0xed;
        modulus[31] = 0x7f;
        assert!(!is_x25519_key(&key(modulus)));
        for u in LOW_ORDER_U {
            let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(u));
            assert!(!shared.was_contributory());
            assert!(!is_x25519_key(&key(u)));
        }
    }
}
