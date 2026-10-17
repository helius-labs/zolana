use anyhow::{bail, ensure, Context as _, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_indexer_api::{Base64String, Hash};
use zolana_keypair::X25519Pubkey;
use zolana_ring_client::{
    auditor_view_tag,
    rpc::{
        auditor_key_attestation, CreateAuditorKeyRequest, CreateAuditorKeyResponse,
        DecryptedTransaction, DecryptedTransactionsPage, GetDecryptedTransactionsRequest,
        GetDecryptedTransactionsResponse, RingState, RingStatusRequest, RingStatusResponse,
        CREATE_AUDITOR_KEY, GET_DECRYPTED_TRANSACTIONS, RING_STATUS,
    },
};

use crate::{line, probe, wait_for, Context, Probe};

/// More pages than a ring rpc returns for one transaction search.
const MAX_PAGES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Pinned(Address),
    Unpinned,
    Refuse,
}

pub struct AttestedAuditorKey {
    pub auditor_pk: X25519Pubkey,
    pub service_pubkey: Address,
}

pub struct RingRpcClient {
    url: String,
    http: reqwest::blocking::Client,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

/// Answers before the ring has a config, so a pipeline stops before `init` pins an
/// auditor the service does not hold.
pub fn run_check(ctx: &Context) -> Result<()> {
    let client = ctx.ring_rpc();
    let held = match client.state(ctx.ring.program_id())? {
        RingState::Served => "serves this ring",
        _ => "holds a key for the ring, `init` pins it",
    };
    line("ring rpc", format_args!("{} {held}", client.url));
    Ok(())
}

impl AttestedAuditorKey {
    pub fn require(self, trust: Trust) -> Result<X25519Pubkey> {
        let actual = self.service_pubkey;
        match trust {
            Trust::Pinned(pinned) => ensure!(
                pinned == actual,
                "the ring rpc signs with {actual} but ring.toml pins {pinned}"
            ),
            Trust::Unpinned => {}
            Trust::Refuse => bail!(
                "ring.toml pins no ring rpc service key, the rpc signs with {actual}. Put it in ring_rpc_pubkey after confirming it out of band, or pass --trust-ring-rpc for a local instance"
            ),
        }
        Ok(self.auditor_pk)
    }
}

impl RingRpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            http: probe::http(probe::CONNECT_TIMEOUT, probe::TOTAL_TIMEOUT),
        }
    }

    /// Verified against the service key the response names, the caller decides whether to trust it.
    pub fn release_auditor_key(
        &self,
        ring: Address,
        genesis_hash: [u8; 32],
        authority: &dyn Signer,
    ) -> Result<AttestedAuditorKey> {
        let request = CreateAuditorKeyRequest::for_ring(ring, genesis_hash).sign(authority)?;
        let created: CreateAuditorKeyResponse = self.call(CREATE_AUDITOR_KEY, request)?;
        let service_pubkey = created.service_pubkey.0;
        let auditor_pk = *created.auditor_pubkey.as_key();
        let attestation = auditor_key_attestation(&ring, &auditor_pk);
        let url = &self.url;
        ensure!(
            created.signature.0.verify(service_pubkey.as_ref(), &attestation),
            "the ring rpc at {url} returned an auditor key its service key {service_pubkey} did not sign"
        );
        Ok(AttestedAuditorKey {
            auditor_pk,
            service_pubkey,
        })
    }

    /// Unsigned, `release_auditor_key` is the attested path `init` pins from.
    pub fn ring_status(&self, ring: Address) -> Result<RingStatusResponse> {
        let ring_program_id = ring.to_bytes().into();
        self.call(RING_STATUS, RingStatusRequest { ring_program_id })
    }

    pub fn check_serves(&self, ring: Address) -> Result<()> {
        ensure!(
            self.state(ring)? == RingState::Served,
            "the ring has no config yet, run `zolana-ring init` before `transact`"
        );
        Ok(())
    }

    /// A failed read is retried, a transaction the service skipped is final.
    pub fn wait_for_decrypted(
        &self,
        ring: Address,
        reader: &dyn Signer,
        signature: Signature,
        event_index: u16,
    ) -> Result<DecryptedTransaction> {
        wait_for("ring rpc to open the transaction", || {
            find_decrypted(signature, event_index, |cursor| {
                let mut request = GetDecryptedTransactionsRequest::read(ring);
                if let Some(cursor) = cursor {
                    request = request.with_cursor(cursor)?;
                }
                let request = request.sign(reader)?;
                let page: GetDecryptedTransactionsResponse =
                    self.call(GET_DECRYPTED_TRANSACTIONS, request)?;
                Ok(page.value)
            })
        })
    }

    /// A service that holds another key for this ring can open nothing here.
    fn state(&self, ring: Address) -> Result<RingState> {
        let status = self.ring_status(ring)?;
        let expected_tag = status
            .config_auditor_pubkey
            .map(|key| Hash(auditor_view_tag(key.as_key())))
            .unwrap_or_default();
        let url = &self.url;
        ensure!(status.state != RingState::ForeignAuditor, "the ring rpc at {url} holds another auditor key for this ring than the one its config names ({expected_tag}). A config fixes its auditor when it is created, so this service can never open the ring. Serve the ring from a ring rpc holding its key, or deploy a new ring");
        Ok(status.state)
    }

    fn call<T: DeserializeOwned>(&self, method: &str, params: impl Serialize) -> Result<T> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response: JsonRpcResponse<T> = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .with_context(|| format!("no ring rpc answers at {}", self.url))?
            .error_for_status()?
            .json()?;
        if let Some(error) = response.error {
            bail!("ring rpc {method} failed, {error}");
        }
        response
            .result
            .with_context(|| format!("ring rpc {method} returned no result"))
    }
}

/// Walks pages until the requested event appears. A page error is a retry.
/// A repeated cursor is an error.
fn find_decrypted(
    signature: Signature,
    event_index: u16,
    mut page: impl FnMut(Option<Base64String>) -> Result<DecryptedTransactionsPage>,
) -> Result<Probe<DecryptedTransaction>> {
    let mut cursor = None;
    for _ in 0..MAX_PAGES {
        let read = match page(cursor.clone()) {
            Ok(read) => read,
            Err(error) => return Ok(Probe::Retry(error)),
        };
        if let Some(item) = read
            .items
            .into_iter()
            .find(|item| item.tx_signature.0 == signature && item.event_index == event_index)
        {
            return Ok(Probe::Ready(item));
        }
        for skipped in read.skipped {
            let reason = skipped.reason;
            ensure!(
                skipped.tx_signature.0 != signature || skipped.event_index != event_index,
                "ring rpc could not open {signature} event {event_index}, {reason:?}"
            );
        }
        let Some(next) = read.cursor else {
            return Ok(Probe::NotYet);
        };
        ensure!(
            cursor.as_ref() != Some(&next),
            "the ring rpc repeated its cursor"
        );
        cursor = Some(next);
    }
    bail!("the ring rpc returned more than {MAX_PAGES} pages")
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use zolana_keypair::X25519Secret;
    use zolana_ring_client::rpc::{SkippedReason, SkippedTransaction};

    use super::*;

    const SERVICE: Address = Address::new_from_array([7u8; 32]);

    fn attested(auditor_pk: X25519Pubkey) -> AttestedAuditorKey {
        AttestedAuditorKey {
            auditor_pk,
            service_pubkey: SERVICE,
        }
    }

    #[test]
    fn trust_accepts_the_pinned_key_or_an_explicit_waiver() {
        let auditor_pk = X25519Secret::new().pubkey();
        let required = |trust| attested(auditor_pk).require(trust);
        assert_eq!(
            required(Trust::Pinned(SERVICE)).expect("pinned"),
            auditor_pk
        );
        assert_eq!(required(Trust::Unpinned).expect("unpinned"), auditor_pk);
        let mismatch = required(Trust::Pinned(Address::new_from_array([8u8; 32])));
        assert!(mismatch
            .expect_err("other")
            .to_string()
            .contains("but ring.toml pins"));
        let refused = required(Trust::Refuse).expect_err("refused").to_string();
        assert!(refused.contains("--trust-ring-rpc"), "{refused}");
    }

    fn page(cursor: Option<u8>, items: Vec<DecryptedTransaction>) -> DecryptedTransactionsPage {
        DecryptedTransactionsPage {
            items,
            skipped: Vec::new(),
            cursor: cursor.map(|cursor| vec![cursor].into()),
        }
    }

    fn opened(signature: Signature) -> DecryptedTransaction {
        DecryptedTransaction {
            anonymous: None,
            slot: 1,
            tx_signature: signature.into(),
            event_index: 0,
            tx_viewing_pk: Vec::new().into(),
            outputs: Vec::new(),
            output_openings: Vec::new(),
            undecryptable_slots: Vec::new(),
            nullifiers: Vec::new(),
            signers: Vec::new(),
            withdrawals: Vec::new(),
        }
    }

    #[test]
    fn the_page_walk_follows_cursors_to_the_transaction() {
        let wanted = Signature::from([3; 64]);
        let pages = Cell::new(0u8);
        let found = find_decrypted(wanted, 0, |cursor| {
            let index = pages.get();
            pages.set(index + 1);
            assert_eq!(cursor, (index > 0).then(|| vec![index].into()));
            Ok(match index {
                0 => page(Some(1), vec![opened(Signature::default())]),
                _ => page(None, vec![opened(wanted)]),
            })
        })
        .expect("walk");
        assert!(matches!(found, Probe::Ready(item) if item.tx_signature.0 == wanted));
        let absent = find_decrypted(wanted, 0, |_| Ok(page(None, Vec::new()))).expect("walk");
        assert!(matches!(absent, Probe::NotYet));
    }

    #[test]
    fn the_page_walk_matches_the_event_within_a_signature() {
        let wanted = Signature::from([3; 64]);
        let mut other = opened(wanted);
        other.event_index = 1;
        let mut pages = 0;
        let found = find_decrypted(wanted, 0, |_| {
            pages += 1;
            Ok(if pages == 1 {
                DecryptedTransactionsPage {
                    skipped: vec![SkippedTransaction {
                        slot: 1,
                        tx_signature: wanted.into(),
                        event_index: 1,
                        reason: SkippedReason::InvalidAuditData,
                    }],
                    ..page(Some(1), vec![other.clone()])
                }
            } else {
                page(None, vec![opened(wanted)])
            })
        })
        .expect("walk");
        assert!(matches!(found, Probe::Ready(item) if item.event_index == 0));
        assert_eq!(pages, 2);
    }

    #[test]
    fn a_repeated_cursor_or_an_endless_walk_is_refused() {
        let wanted = Signature::from([3; 64]);
        let repeated = find_decrypted(wanted, 0, |_| Ok(page(Some(9), Vec::new())));
        let error = repeated.err().expect("repeated cursor").to_string();
        assert_eq!(error, "the ring rpc repeated its cursor");
        let next = Cell::new(0u8);
        let endless = find_decrypted(wanted, 0, |_| {
            next.set(next.get().wrapping_add(1));
            Ok(page(Some(next.get()), Vec::new()))
        });
        let error = endless.err().expect("endless walk").to_string();
        assert!(error.contains("more than 64 pages"), "{error}");
        assert_eq!(usize::from(next.get()), MAX_PAGES);
    }

    #[test]
    fn a_skipped_transaction_is_final_and_a_failed_page_is_retried() {
        let wanted = Signature::from([3; 64]);
        let skipped = find_decrypted(wanted, 0, |_| {
            Ok(DecryptedTransactionsPage {
                skipped: vec![SkippedTransaction {
                    slot: 1,
                    tx_signature: wanted.into(),
                    event_index: 0,
                    reason: SkippedReason::InvalidAuditData,
                }],
                ..page(None, Vec::new())
            })
        });
        assert!(skipped
            .err()
            .expect("skipped")
            .to_string()
            .contains("could not open"));
        let failed = find_decrypted(wanted, 0, |_| bail!("down")).expect("retry");
        assert!(matches!(failed, Probe::Retry(error) if error.to_string() == "down"));
    }
}
