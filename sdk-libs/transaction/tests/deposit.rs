//! A public deposit into a wallet's private balance.

use solana_address::Address;
use zolana_keypair::{ShieldedKeypair, SigningKey};
use zolana_program::instruction::{AssetDeposit, DepositAsset, DepositSplAccounts};
use zolana_transaction::instructions::deposit::deposit_to;

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
        .expect("fixture keypair")
}

#[test]
fn a_wallet_deposit_is_owned_by_the_recipient_and_carries_the_tag_its_wallet_scans_for() {
    let recipient = keypair(3);
    let address = recipient.shielded_address().unwrap();
    let spl = DepositAsset::Spl(DepositSplAccounts {
        mint: Address::new_from_array([4; 32]),
        user_token: Address::new_from_array([5; 32]),
        token_program: Address::new_from_array([6; 32]),
    });
    for asset in [DepositAsset::Sol, spl] {
        assert_eq!(
            deposit_to(asset, 9, &address).unwrap(),
            AssetDeposit {
                asset,
                view_tag: recipient.recipient_bootstrap_view_tag(),
                owner: recipient.owner_hash().unwrap(),
                amount: 9,
                memo: None,
            }
        );
    }
    assert_ne!(
        deposit_to(
            DepositAsset::Sol,
            9,
            &keypair(4).shielded_address().unwrap()
        )
        .unwrap(),
        deposit_to(DepositAsset::Sol, 9, &address).unwrap()
    );
}
