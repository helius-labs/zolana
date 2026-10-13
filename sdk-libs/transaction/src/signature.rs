/// An Ed25519 signature over the 32-byte transact message hash, together with
/// the public key that produced it.
///
/// It lives here rather than beside the wallet authority that produces it
/// because the prover consumes it directly when assembling a custom-ring
/// transfer whose owner signature is verified in the proof, and the prover
/// sits below the wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519Authorization {
    pub pubkey: [u8; 32],
    pub signature: [u8; 64],
}
