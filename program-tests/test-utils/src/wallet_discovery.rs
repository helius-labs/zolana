//! Wallet-discovery assertion shared by the litesvm and test-validator deposit
//! assert helpers.

use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_program_test::DepositOutput;
use zolana_transaction::{SyncWalletAuthority, Wallet, DEFAULT_TAG_WINDOW};

/// Sync the recipient wallet over a settled deposit event and assert it
/// discovers exactly one new UTXO mirroring the event. `expected_mint`
/// additionally pins the UTXO asset for SPL deposits; `label` is the deposit
/// kind used in the discovery assertion message ("deposit" / "SPL deposit").
/// Litesvm backends carry no real signature and pass `Signature::default()`.
#[track_caller]
pub(crate) fn assert_wallet_discovers<A: SyncWalletAuthority + ?Sized>(
    recipient: &mut Wallet,
    authority: &A,
    event: &DepositOutput,
    signature: Signature,
    memo: &Option<Vec<u8>>,
    expected_mint: Option<&Pubkey>,
    label: &str,
) {
    let before = recipient.utxos.len();
    recipient
        .sync(
            authority,
            &[event.to_shielded_transaction(signature)],
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
    assert_eq!(
        utxo.output_context.hash, event.utxo_hash,
        "wallet UTXO hash"
    );
    if let Some(mint) = expected_mint {
        assert_eq!(
            utxo.utxo.asset.to_bytes(),
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
