//! The auditor page, rendered on the server from the same data the JSON-RPC
//! methods return. No script runs in the browser; the page refreshes itself.

use std::collections::{HashMap, HashSet};

use maud::{html, Markup, PreEscaped, DOCTYPE};
use solana_address::Address;
use zolana_indexer_api::{Base64String, Hash, SerializablePubkey};

use crate::api::{DecryptedOutput, DecryptedTransaction, GetDecryptedTransactionsResponse};

/// The all-zero mint, SOL's asset in the registry.
const SOL_MINT: [u8; 32] = [0u8; 32];
const REFRESH_SECONDS: u32 = 5;
const STYLE: &str = include_str!("page.css");

/// One rendering of the auditor's view: a page of transactions plus what the
/// reader needs to place it.
pub struct AuditorPage<'a> {
    pub auditor_view_tag: Hash,
    /// The ring shown when the instance serves several.
    pub ring: Option<Address>,
    pub page: &'a GetDecryptedTransactionsResponse,
    /// The cursor this page was fetched with, if any.
    pub cursor: Option<&'a str>,
}

impl AuditorPage<'_> {
    pub fn render(&self) -> Markup {
        let items = &self.page.value.items;
        let own_keys = own_viewing_keys(items);
        html! {
            (DOCTYPE)
            html lang="en" {
                head {
                    meta charset="utf-8";
                    meta name="viewport" content="width=device-width, initial-scale=1";
                    @if self.cursor.is_none() {
                        meta http-equiv="refresh" content=(REFRESH_SECONDS);
                    }
                    title { "Ring Auditor" }
                    style { (PreEscaped(STYLE)) }
                }
                body {
                    header {
                        h1 { "Ring Auditor" }
                        span class="muted" {
                            @if let Some(ring) = self.ring { "ring " code { (ring) } " · " }
                            "auditor view tag " code { (self.auditor_view_tag) }
                            " · indexer slot " (self.page.context.slot)
                            " · " (items.len()) " transaction" @if items.len() != 1 { "s" }
                            @if self.cursor.is_some() { " (older page)" }
                        }
                    }
                    main {
                        @if items.is_empty() {
                            p class="empty" { "No audited transactions yet." }
                        }
                        @for tx in items.iter().rev() {
                            (transaction_card(tx, &own_keys))
                        }
                        (skipped(self.page))
                        (pager(self))
                    }
                    footer {
                        em { "from" } " is the transaction's Solana signers, which on the eddsa rail are the owners of the spent inputs; "
                        em { "to" } " is the viewing key each output was encrypted to, the value a wallet publishes as its shielded address. Amounts are lamports."
                    }
                }
            }
        }
    }
}

/// A recipient key that shows up under the same signer more than once is that
/// sender's own key, so its slots are change.
fn own_viewing_keys(items: &[DecryptedTransaction]) -> HashSet<(String, String)> {
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    for tx in items {
        for signer in &tx.signers {
            for output in &tx.outputs {
                *seen
                    .entry((
                        signer.to_string(),
                        hex::encode(&output.recipient_viewing_pk.0),
                    ))
                    .or_default() += 1;
            }
        }
    }
    seen.into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(key, _)| key)
        .collect()
}

fn transaction_card(tx: &DecryptedTransaction, own_keys: &HashSet<(String, String)>) -> Markup {
    let is_change = |output: &DecryptedOutput| {
        let key = hex::encode(&output.recipient_viewing_pk.0);
        tx.signers
            .iter()
            .any(|signer| own_keys.contains(&(signer.to_string(), key.clone())))
    };
    html! {
        section class="card" {
            h2 {
                code title=(tx.tx_signature) { (short(&tx.tx_signature.to_string(), 14)) }
                span class="muted" { "slot " (tx.slot) }
                span class="muted" {
                    "from "
                    @if tx.signers.is_empty() { "unknown (rpc no longer holds the transaction)" }
                    @for signer in &tx.signers {
                        code title=(signer) { (short(&signer.to_string(), 8)) } " "
                    }
                }
                span class="muted" {
                    "tx viewing pk " code { (short(&hex::encode(&tx.tx_viewing_pk.0), 8)) }
                }
            }
            table {
                thead {
                    tr {
                        th class="num" { "slot" }
                        th { "to (viewing pk)" }
                        th { "asset" }
                        th class="num" { "amount" }
                        th { "blinding" }
                        th { "ring program" }
                    }
                }
                tbody {
                    @for output in &tx.outputs {
                        tr {
                            td class="num" { (output.slot_index) }
                            td {
                                code title=(hex::encode(&output.recipient_viewing_pk.0)) {
                                    (short(&hex::encode(&output.recipient_viewing_pk.0), 8))
                                }
                                @if is_change(output) { " " span class="muted" { "(change)" } }
                            }
                            td { (asset(&output.asset)) }
                            td class="num" { (lamports(output.amount)) }
                            td { code { (short(&hex::encode(&output.blinding.0), 10)) } }
                            td { code { (output.ring_program_id.as_ref().map(ToString::to_string).unwrap_or_default()) } }
                        }
                    }
                }
            }
            @if !tx.undecryptable_slots.is_empty() {
                p class="warn" {
                    "undecryptable slots: "
                    (tx.undecryptable_slots.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))
                }
            }
            p class="muted" {
                "nullifiers "
                @for nullifier in &tx.nullifiers {
                    code title=(nullifier) { (short(&nullifier.to_string(), 6)) } " "
                }
            }
        }
    }
}

fn skipped(page: &GetDecryptedTransactionsResponse) -> Markup {
    let skipped = &page.value.skipped;
    html! {
        @if !skipped.is_empty() {
            section class="card" {
                h2 { "Skipped" }
                table {
                    tbody {
                        @for item in skipped {
                            tr {
                                td { code title=(item.tx_signature) { (short(&item.tx_signature.to_string(), 14)) } }
                                td class="num" { (item.slot) }
                                td class="warn" { (item.reason) }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn pager(page: &AuditorPage<'_>) -> Markup {
    let older = page.page.value.cursor.as_ref().map(base64_query);
    let ring = page
        .ring
        .map(|ring| format!("ring={ring}&"))
        .unwrap_or_default();
    html! {
        nav class="pager" {
            @if page.cursor.is_some() { a href={ "/?" (ring) } { "newest" } " " }
            @if let Some(older) = older { a href={ "/?" (ring) "cursor=" (older) } { "older" } }
        }
    }
}

fn base64_query(cursor: &Base64String) -> String {
    // The cursor is opaque bytes; base64url keeps it inside a query string.
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cursor.0)
}

/// Inverse of [`base64_query`].
pub fn cursor_from_query(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()
}

fn asset(mint: &SerializablePubkey) -> Markup {
    if mint.0.to_bytes() == SOL_MINT {
        html! { "SOL" }
    } else {
        html! { code { (mint) } }
    }
}

fn lamports(amount: u64) -> String {
    let whole = amount / 1_000_000_000;
    let fraction = amount % 1_000_000_000;
    let fraction = format!("{fraction:09}");
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{amount} ({whole} SOL)")
    } else {
        format!("{amount} ({whole}.{fraction} SOL)")
    }
}

fn short(text: &str, keep: usize) -> String {
    if text.len() > 2 * keep {
        format!("{}…{}", &text[..keep], &text[text.len() - keep..])
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lamports_render_whole_and_fractional_sol() {
        assert_eq!(lamports(1_000_000_000), "1000000000 (1 SOL)");
        assert_eq!(lamports(1_500_000_000), "1500000000 (1.5 SOL)");
        assert_eq!(lamports(7), "7 (0.000000007 SOL)");
    }

    #[test]
    fn cursor_round_trips_through_the_query_string() {
        let cursor = Base64String(vec![0, 1, 254, 255, 7]);
        assert_eq!(
            cursor_from_query(&base64_query(&cursor)).expect("decode"),
            cursor.0
        );
    }
}
