use zolana_keypair::P256Pubkey;

/// A P-256 signature over a 32-byte message hash, together with the public key
/// that produced it.
///
/// It lives here rather than beside the wallet authority that produces it
/// because the prover consumes it directly when assembling a custom-ring P-256
/// transfer, and the prover sits below the wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256Signature {
    pub pubkey: P256Pubkey,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}
