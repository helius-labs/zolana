//! The descriptor used both by proof admission and by binary inspection.
use feature_gate::{features, hashes_with_prefix, CircuitFeature};
use spr_interface::{
    shape::CONFIDENTIAL_EDDSA_SHAPES,
    verifying_keys::{CircuitId, PROVING_KEY_SHA256S},
};

const CONFIDENTIAL_EDDSA_KEYS: [[u8; 32]; CONFIDENTIAL_EDDSA_SHAPES.len()] =
    hashes_with_prefix(PROVING_KEY_SHA256S, "transfer_confidential_eddsa_");

pub const CONFIDENTIAL_EDDSA: CircuitFeature =
    features::confidential_eddsa(&CONFIDENTIAL_EDDSA_KEYS);

// Exporting retains the record, as with VK setup markers. `#[used]` adds
// GNU-retain ELF flags that the SBF loader does not accept.
#[unsafe(export_name = "spr_feature_gate_confidential_eddsa_v1")]
pub static CONFIDENTIAL_EDDSA_METADATA: [u8; CONFIDENTIAL_EDDSA.encoded_len()] =
    CONFIDENTIAL_EDDSA.encode();

pub fn circuit_enabled(circuit: CircuitId) -> bool {
    if circuit.eddsa_owner_pk().is_none() {
        return true;
    }
    circuit
        .proving_key_sha256()
        .is_some_and(|hash| CONFIDENTIAL_EDDSA.allows(hash))
}
