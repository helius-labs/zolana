use serde::Deserialize;

/// The body of `GET /tee/v1/attestation`.
#[derive(Clone, Debug, Deserialize)]
pub struct Evidence {
    #[serde(with = "hex")]
    pub quote: Vec<u8>,
    pub event_log: Vec<EventLogEntry>,
    #[serde(default)]
    pub vm_config: String,
    pub collateral: Collateral,
    #[serde(with = "hex")]
    pub hpke_public_key: [u8; 32],
    /// The raw NRAS response the prover verified inside the TEE.
    pub gpu: Option<String>,
}

/// One dstack event log entry, with an empty `event_payload` for boot events.
#[derive(Clone, Debug, Deserialize)]
pub struct EventLogEntry {
    pub imr: u32,
    pub event_type: u32,
    #[serde(default, with = "hex")]
    pub digest: Vec<u8>,
    pub event: String,
    #[serde(with = "hex")]
    pub event_payload: Vec<u8>,
}

/// dcap-qvl `QuoteCollateralV3` in hex, Intel signed so the prover may relay it.
#[derive(Clone, Debug, Deserialize)]
pub struct Collateral {
    pub pck_crl_issuer_chain: String,
    #[serde(with = "hex")]
    pub root_ca_crl: Vec<u8>,
    #[serde(with = "hex")]
    pub pck_crl: Vec<u8>,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    #[serde(with = "hex")]
    pub tcb_info_signature: Vec<u8>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    #[serde(with = "hex")]
    pub qe_identity_signature: Vec<u8>,
}

impl From<Collateral> for dcap_qvl::QuoteCollateralV3 {
    fn from(c: Collateral) -> Self {
        Self {
            pck_crl_issuer_chain: c.pck_crl_issuer_chain,
            root_ca_crl: c.root_ca_crl,
            pck_crl: c.pck_crl,
            tcb_info_issuer_chain: c.tcb_info_issuer_chain,
            tcb_info: c.tcb_info,
            tcb_info_signature: c.tcb_info_signature,
            qe_identity_issuer_chain: c.qe_identity_issuer_chain,
            qe_identity: c.qe_identity,
            qe_identity_signature: c.qe_identity_signature,
            pck_certificate_chain: None,
        }
    }
}
