use solana_address::Address;
use zk_program_sdk::{circuit::Field, ZkCircuit};
use zolana_transaction::{instructions::transact::SettlementTarget, Mint};

use super::{
    fixtures::{
        broken, Asserted, Checked, Shape, COUNTER_OVERFLOWS, LEAVES, NO_INPUT, NO_TREE,
        PRIVATE_TX_HASH, PUBLIC_HASH, TRANSACTION_HASH,
    },
    reference::Expected,
    vectors::{
        forgotten, fund, funds, payments, refresh, refreshes, settles, swept, unspent, Named,
    },
    wallets::{address, blinding, Spent, SENDER, STRANGER},
};
use crate::harness::fixture::{native, rule_broken, Refusal};

const BURN_LEAVES: &str = "a burned token utxo leaves a balance";

fn honest<P: Shape>(named: Named<P>) -> Vec<(&'static str, Result<(), Refusal>)>
where
    Asserted<P>: ZkCircuit,
{
    named
        .into_iter()
        .map(|(name, program)| (name, native(&Asserted::honest(program))))
        .collect()
}

fn holding<P>(named: Named<P>) -> Vec<(&'static str, Result<(), Refusal>)> {
    named.into_iter().map(|(name, _)| (name, Ok(()))).collect()
}

fn against<P: Shape>(program: P, expected: Expected) -> Result<(), Refusal>
where
    Asserted<P>: ZkCircuit,
{
    native(&Asserted { program, expected })
}

#[test]
fn every_shape_reproduces_the_native_private_transaction_and_public_hashes() {
    assert_eq!(
        (
            honest(refreshes()),
            honest(payments()),
            honest(funds()),
            honest(settles()),
            native(&Asserted::honest(swept::<true>(300))),
        ),
        (
            holding(refreshes()),
            holding(payments()),
            holding(funds()),
            holding(settles()),
            Ok(()),
        )
    );
}

#[test]
fn each_hash_that_differs_from_the_native_one_breaks_exactly_its_rule() {
    let (_, program) = refreshes().swap_remove(0);
    let native_hashes = program.reference().expected();
    let one = Field::from(1u64);
    assert_eq!(
        [
            against(
                program.clone(),
                Expected {
                    private_tx_hash: native_hashes.private_tx_hash + one,
                    ..native_hashes
                }
            ),
            against(
                program.clone(),
                Expected {
                    transaction_hash: native_hashes.transaction_hash + one,
                    ..native_hashes
                }
            ),
            against(
                program,
                Expected {
                    public_hash: native_hashes.public_hash + one,
                    ..native_hashes
                }
            ),
        ],
        [
            Err(broken(PRIVATE_TX_HASH)),
            Err(broken(TRANSACTION_HASH)),
            Err(broken(PUBLIC_HASH)),
        ]
    );
}

#[test]
fn the_hashes_bind_the_blinding_seed_the_output_tree_the_transfers_and_the_public_inputs() {
    let (_, refreshed) = refreshes().swap_remove(0);
    let (_, over_latest) = refreshes().swap_remove(3);
    let (_, settled) = settles().swap_remove(0);
    let (_, paid) = payments().swap_remove(0);
    let another_seed = {
        let mut reference = refreshed.reference();
        reference.blinding_seed = blinding(0x77);
        reference.expected()
    };
    let the_latest_tree = {
        let mut reference = over_latest.reference();
        reference.output_tree_id = 7;
        reference.expected()
    };
    let another_account = {
        let mut reference = settled.reference();
        reference.transfers[0].target = SettlementTarget::Sol {
            user_sol_account: Address::new_from_array([0x42; 32]),
        };
        reference.expected()
    };
    let another_recipient = {
        let mut reference = paid.reference();
        reference.public = vec![address(STRANGER).owner_hash().expect("owner hash")];
        reference.expected()
    };
    assert_eq!(
        [
            against(refreshed, another_seed),
            against(over_latest, the_latest_tree),
            against(settled, another_account),
            against(paid, another_recipient),
        ],
        [
            Err(broken(PRIVATE_TX_HASH)),
            Err(broken(PRIVATE_TX_HASH)),
            Err(broken(TRANSACTION_HASH)),
            Err(broken(PUBLIC_HASH)),
        ]
    );
}

#[test]
fn a_malformed_transaction_breaks_exactly_its_rule() {
    let no_tree = refresh(Spent::token(SENDER, Mint::SOL, 5, 0), None);
    assert_eq!(
        [
            native(&Checked {
                program: forgotten()
            }),
            native(&Checked { program: unspent() }),
            native(&Checked { program: no_tree }),
            native(&Checked {
                program: fund(300, 0, u64::MAX, 100)
            }),
            native(&Checked {
                program: swept::<false>(300)
            }),
        ],
        [
            Err(broken(LEAVES)),
            Err(broken(NO_INPUT)),
            Err(broken(NO_TREE)),
            Err(broken(COUNTER_OVERFLOWS)),
            Err(rule_broken(BURN_LEAVES, super::fixtures::FILE)),
        ]
    );
}
