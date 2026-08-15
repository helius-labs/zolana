//! The transport seam between a shielded backend and Turnkey.
//!
//! The backends in this crate depend on this trait rather than on
//! `turnkey_client`, so the same code paths that run against the live API also
//! run against an in-process signer in tests, and a caller that already owns a
//! Turnkey transport can plug it in.

use async_trait::async_trait;

use crate::error::TurnkeyKeypairError;

/// The curve of a Turnkey private key, narrowed to the two this crate can use.
///
/// Turnkey also issues secp256k1 keys; a shielded owner is never on that curve,
/// so a secp256k1 key is reported as a [`TurnkeyCurve::Other`] mismatch rather
/// than silently accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnkeyCurve {
    Ed25519,
    P256,
    Other,
}

/// Which `hash_function` a `SIGN_RAW_PAYLOAD_V2` request carries.
///
/// Only two values are reachable from here. Ed25519 requires
/// `HASH_FUNCTION_NOT_APPLICABLE` because RFC 8032 fixes the hash, and the
/// P-256 shielded rail signs an already-computed 32-byte digest, so it requires
/// `HASH_FUNCTION_NO_OP`. Letting Turnkey hash the payload instead would sign a
/// different message than the one the SPP proof commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadHashFunction {
    NotApplicable,
    NoOp,
}

/// Addresses one Turnkey private key: the organization the activity is stamped
/// against, and the key inside it.
///
/// Neither field is secret, and for the ed25519 rail the pair is the *complete*
/// persistent state of a shielded identity — the signing key stays in Turnkey
/// and both role secrets re-derive from it, so a service that stores only this
/// can rebuild the wallet from nothing. See
/// [`crate::TurnkeyEd25519ShieldedKeypair`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TurnkeyKeyRef {
    /// The sub-organization holding the key. Activities are stamped in the
    /// child's context, not the parent's.
    pub organization_id: String,
    pub private_key_id: String,
}

impl TurnkeyKeyRef {
    pub fn new(organization_id: impl Into<String>, private_key_id: impl Into<String>) -> Self {
        Self {
            organization_id: organization_id.into(),
            private_key_id: private_key_id.into(),
        }
    }
}

/// The public half of a Turnkey private key, as returned by `get_private_key`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteKey {
    pub curve: TurnkeyCurve,
    /// Raw public-key bytes, hex-decoded from the response. 32 bytes for
    /// ed25519; SEC1 compressed (33) or uncompressed (65) for P-256.
    pub public_key: Vec<u8>,
}

/// The two signature components Turnkey returns from `SIGN_RAW_PAYLOAD_V2`,
/// hex-decoded but otherwise untouched.
///
/// Deliberately not a `[u8; 64]`: the two rails disagree about how a short
/// component must be widened, so the decision belongs to this crate's codec
/// rather than to the transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawSignature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

/// The Turnkey activities a shielded backend needs. This is the whole surface:
/// read a key's public half, and sign a raw payload with it.
///
/// Notably absent is any key-agreement call, because Turnkey has none. That is
/// why the P-256 rail cannot be rooted in Turnkey — see
/// [`crate::TurnkeyP256ShieldedKeypair`].
#[async_trait]
pub trait TurnkeyActivities: Send + Sync {
    async fn get_private_key(
        &self,
        organization_id: &str,
        private_key_id: &str,
    ) -> Result<RemoteKey, TurnkeyKeypairError>;

    async fn sign_raw_payload(
        &self,
        organization_id: &str,
        private_key_id: &str,
        payload: &[u8],
        hash_function: PayloadHashFunction,
    ) -> Result<RawSignature, TurnkeyKeypairError>;
}
