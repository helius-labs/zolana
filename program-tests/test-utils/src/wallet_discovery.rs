//! Wallet-discovery assertion shared by the litesvm and test-validator deposit
//! assert helpers.

use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_program_test::DepositOutput;
use zolana_wallet::{SyncWalletAuthority, Wallet, DEFAULT_TAG_WINDOW};

/// One settled deposit as the discovery assert reads it.
pub(crate) struct DiscoveredDeposit<'a> {
    pub event: &'a DepositOutput,
    /// Litesvm backends carry no real signature and pass `Signature::default()`.
    pub signature: Signature,
    /// Raw id of the deposit's tree. The published commitment folds it in, so
    /// the wallet only rediscovers the note when it re-hashes under the same id.
    pub tree_id: u16,
    pub memo: &'a Option<Vec<u8>>,
    /// Pins the UTXO asset for SPL deposits.
    pub expected_mint: Option<&'a Pubkey>,
    /// Deposit kind named in the discovery assertion message ("deposit" /
    /// "SPL deposit").
    pub label: &'a str,
}

/// Sync the recipient wallet over a settled deposit event and assert it
/// discovers exactly one new UTXO mirroring the event.
#[track_caller]
pub(crate) fn assert_wallet_discovers<A: SyncWalletAuthority + ?Sized>(
    recipient: &mut Wallet,
    authority: &A,
    deposit: DiscoveredDeposit<'_>,
) {
    let DiscoveredDeposit {
        event,
        signature,
        tree_id,
        memo,
        expected_mint,
        label,
    } = deposit;
    let before = recipient.utxos.len();
    recipient
        .sync(
            authority,
            &[event.to_shielded_transaction(signature, tree_id)],
            0,
            DEFAULT_TAG_WINDOW,
        )
        .expect("wallet discovery");
    assert_eq!(
        recipient.utxos.len(),
        before + 1,
        "recipient wallet must discover the {label}"
    );
    let utxo = recipient.utxos.last().expect("discovered UTXO");
    assert_eq!(utxo.utxo_hash, event.utxo_hash, "wallet UTXO hash");
    if let Some(mint) = expected_mint {
        assert_eq!(
            utxo.utxo.asset.asset.to_bytes(),
            mint.to_bytes(),
            "wallet UTXO asset is the mint"
        );
    }
    assert_eq!(utxo.utxo.amount, event.output.amount, "wallet UTXO amount");
    assert_eq!(
        utxo.utxo.data.memo().map(<[u8]>::to_vec),
        *memo,
        "wallet UTXO memo mirrors the deposited memo"
    );
}
