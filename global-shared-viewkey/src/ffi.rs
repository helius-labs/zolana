use std::os::raw::c_int;

use zeroize::Zeroizing;

use crate::error::GlobalSharedViewKeyError;

const SHARE_OVERHEAD: usize = 1;

extern "C" {
    fn shamir_split(
        secret: *const u8,
        secret_len: usize,
        parts: c_int,
        threshold: c_int,
        out: *mut u8,
    ) -> c_int;

    fn shamir_combine(shares: *const u8, k: c_int, share_len: usize, out: *mut u8) -> c_int;
}

pub fn split(
    secret: &[u8],
    parts: u8,
    threshold: u8,
) -> Result<Vec<Zeroizing<Vec<u8>>>, GlobalSharedViewKeyError> {
    if parts < 2 {
        return Err(GlobalSharedViewKeyError::InvalidConfig(
            "parts must be >= 2",
        ));
    }
    if threshold < 2 || threshold > parts {
        return Err(GlobalSharedViewKeyError::InvalidConfig(
            "threshold must be in 2..=parts",
        ));
    }
    if secret.is_empty() {
        return Err(GlobalSharedViewKeyError::InvalidConfig(
            "secret must be non-empty",
        ));
    }

    let share_len = secret.len() + SHARE_OVERHEAD;
    let mut out = Zeroizing::new(vec![0u8; parts as usize * share_len]);
    let rc = unsafe {
        shamir_split(
            secret.as_ptr(),
            secret.len(),
            c_int::from(parts),
            c_int::from(threshold),
            out.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(GlobalSharedViewKeyError::Shamir("shamir_split failed"));
    }

    Ok(out
        .chunks(share_len)
        .map(|chunk| Zeroizing::new(chunk.to_vec()))
        .collect())
}

pub fn combine<S: AsRef<[u8]>>(
    shares: &[S],
) -> Result<Zeroizing<Vec<u8>>, GlobalSharedViewKeyError> {
    if shares.len() < 2 {
        return Err(GlobalSharedViewKeyError::InvalidConfig(
            "combine needs >= 2 shares",
        ));
    }
    let share_len = shares
        .first()
        .ok_or(GlobalSharedViewKeyError::InvalidConfig(
            "no shares to combine",
        ))?
        .as_ref()
        .len();
    if share_len <= SHARE_OVERHEAD {
        return Err(GlobalSharedViewKeyError::ShortBlob);
    }

    let count = c_int::try_from(shares.len())
        .map_err(|_| GlobalSharedViewKeyError::InvalidConfig("too many shares"))?;

    let mut flat = Zeroizing::new(Vec::with_capacity(shares.len() * share_len));
    for share in shares {
        let bytes = share.as_ref();
        if bytes.len() != share_len {
            return Err(GlobalSharedViewKeyError::ShortBlob);
        }
        flat.extend_from_slice(bytes);
    }

    let mut out = Zeroizing::new(vec![0u8; share_len - SHARE_OVERHEAD]);
    let rc = unsafe { shamir_combine(flat.as_ptr(), count, share_len, out.as_mut_ptr()) };
    if rc < 0 {
        return Err(GlobalSharedViewKeyError::Shamir("shamir_combine failed"));
    }

    out.truncate(rc as usize);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_then_combine_recovers_secret() {
        let secret = [7u8; 32];
        let shares = split(&secret, 3, 2).expect("split");
        assert_eq!(shares.len(), 3);
        assert!(shares.iter().all(|s| s.len() == 33));

        let quorum: Vec<Vec<u8>> = shares.iter().take(2).map(|s| s.to_vec()).collect();
        let recovered = combine(&quorum).expect("combine");
        assert_eq!(recovered.as_slice(), secret.as_slice());
    }

    #[test]
    fn threshold_below_two_is_rejected() {
        let secret = [1u8; 32];
        assert_eq!(
            split(&secret, 3, 1),
            Err(GlobalSharedViewKeyError::InvalidConfig(
                "threshold must be in 2..=parts"
            ))
        );
    }
}
