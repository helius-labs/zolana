use solana_address::Address;
use zk_program_sdk::{
    circuit::{
        self, poseidon, Asset, Balance, CircuitVar, ConstraintSystem, DataHash, DataUtxo, Field,
        TokenUtxo, Uint, Utxo,
    },
    conversion::{field_bytes, to_bytes, Allocator, ProofInput},
    CircuitError,
};
use zolana_hasher::primitives::hash_bytes;
use zolana_keypair::ShieldedKeypair;
use zolana_transaction::{Mint, WalletUtxo};

mod shared;
use shared::{keypair, spendable, TREE_ID};

const MINT: Mint = Mint::new(Address::new_from_array([4u8; 32]), 4);

fn bytes(value: u64) -> [u8; 32] {
    field_bytes(&Field::from(value))
}

fn native<P: ProofInput>(input: &P) -> P::Circuit {
    input.instantiate(&Allocator::native()).unwrap()
}

fn owner(seed: u8) -> circuit::Owner {
    native(&keypair(seed).shielded_address().unwrap())
}

fn owner_hash(seed: u8) -> [u8; 32] {
    keypair(seed)
        .shielded_address()
        .unwrap()
        .owner_hash()
        .unwrap()
}

fn with_data_hash(
    owner: &ShieldedKeypair,
    mut input: WalletUtxo,
    data_hash: [u8; 32],
) -> WalletUtxo {
    input.data_hash = Some(data_hash);
    input.utxo_hash = input
        .utxo
        .hash(
            &input.nullifier_pubkey,
            &data_hash,
            &[0u8; 32],
            input.tree_id,
        )
        .unwrap();
    input.nullifier = owner
        .nullifier(&input.utxo_hash, &input.utxo.blinding)
        .unwrap();
    input
}

#[derive(Clone, Debug)]
struct Counter {
    value: Uint<64>,
}

impl Default for Counter {
    fn default() -> Self {
        Self {
            value: Uint::zero(),
        }
    }
}

impl DataHash for Counter {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        poseidon(&[self.value.hash()?])
    }
}

fn counter(value: u64) -> Counter {
    Counter { value: uint(value) }
}

fn uint(value: u64) -> Uint<64> {
    Uint::constant(value).unwrap()
}

fn balance_bytes(utxo: &impl Balance) -> [u8; 32] {
    to_bytes(&CircuitVar::from(utxo.balance().unwrap())).unwrap()
}

fn error<T>(result: Result<T, CircuitError>) -> String {
    result.err().map(|e| e.to_string()).unwrap_or_default()
}

#[test]
fn a_data_utxo_follows_its_lifecycle() {
    let counter_hash = to_bytes(&counter(9).hash().unwrap()).unwrap();
    let spent = native(&with_data_hash(
        &keypair(12),
        spendable(&keypair(12), MINT, 7, 0),
        counter_hash,
    ));
    let mut tokens = TokenUtxo::new_mut(&[native(&spendable(&keypair(11), MINT, 50, 1))]).unwrap();
    let mut funded = DataUtxo::<Counter>::new_init(&owner(12), &tokens.asset());
    tokens.transfer(&mut funded, &uint(30)).unwrap();
    let valueless = DataUtxo::<Counter>::new_init(&owner(12), &Asset::sol());
    let mut mutated = DataUtxo::new_mut(&spent, &counter(9)).unwrap();
    mutated.value = uint(10);
    let mut burned = DataUtxo::new_burn(&spent, &counter(9)).unwrap();
    let mut payout = TokenUtxo::new_init(&owner(40), &burned.asset());
    let overpaid = error(burned.transfer(&mut payout, &uint(8)));
    burned.transfer(&mut payout, &uint(7)).unwrap();
    let mut paid_out = TokenUtxo::new_init(&owner(41), &burned.asset());
    burned.transfer_all(&mut paid_out).unwrap();

    assert_eq!(
        (
            (
                to_bytes(&funded.owner().hash().unwrap()).unwrap(),
                balance_bytes(&funded),
                to_bytes(&funded.asset().hash().unwrap()).unwrap(),
            ),
            (
                balance_bytes(&valueless),
                to_bytes(&valueless.asset().hash().unwrap()).unwrap(),
            ),
            to_bytes(&CircuitVar::from(mutated.value.clone())).unwrap(),
            (
                to_bytes(&payout.owner().hash().unwrap()).unwrap(),
                balance_bytes(&payout),
            ),
            balance_bytes(&paid_out),
            overpaid,
            error(DataUtxo::new_mut(&spent, &counter(8))),
            error(DataUtxo::new_burn(
                &native(&spendable(&keypair(12), MINT, 7, 0)),
                &counter(9)
            )),
        ),
        (
            (
                owner_hash(12),
                bytes(30),
                hash_bytes(MINT.asset.as_array()).unwrap()
            ),
            ([0u8; 32], hash_bytes(Mint::SOL.asset.as_array()).unwrap()),
            bytes(10),
            (owner_hash(40), bytes(7)),
            bytes(0),
            "the transfer exceeds the balance".to_string(),
            "the input does not commit to its program state".to_string(),
            "the input does not commit to its program state".to_string(),
        )
    );
}

#[test]
fn a_data_utxo_moves_value_in_every_lifecycle() {
    let counter_hash = to_bytes(&counter(9).hash().unwrap()).unwrap();
    let spent = native(&with_data_hash(
        &keypair(12),
        spendable(&keypair(12), MINT, 7, 0),
        counter_hash,
    ));
    let account = circuit::Bytes::constant(&[6u8; 32]);
    let mut tokens = TokenUtxo::new_mut(&[native(&spendable(&keypair(11), MINT, 50, 1))]).unwrap();
    let mut vault = DataUtxo::new_mut(&spent, &counter(9)).unwrap();
    let mut paid = TokenUtxo::new_init(&owner(40), &vault.asset());
    vault.transfer(&mut paid, &uint(3)).unwrap();
    tokens.transfer(&mut vault, &uint(20)).unwrap();
    vault.deposit(&uint(5), &account).unwrap();
    let mut sol = DataUtxo::<Counter>::new_init(&owner(12), &Asset::sol());
    let other_asset = error(tokens.transfer(&mut sol, &uint(1)));
    let zero_deposit = error(sol.deposit(&uint(0), &account));
    let empty_withdrawal = error(sol.withdraw_all(&account));
    let mut burned = DataUtxo::new_burn(&spent, &counter(9)).unwrap();
    let withdrawn = burned.withdraw_all(&account).unwrap();

    assert_eq!(
        (
            balance_bytes(&paid),
            balance_bytes(&vault),
            balance_bytes(&tokens),
            other_asset,
            zero_deposit,
            empty_withdrawal,
            to_bytes(&CircuitVar::from(withdrawn)).unwrap(),
            balance_bytes(&burned),
        ),
        (
            bytes(3),
            bytes(29),
            bytes(30),
            "the destination holds another asset".to_string(),
            "a public transfer moves a nonzero amount".to_string(),
            "a public transfer moves a nonzero amount".to_string(),
            bytes(7),
            [0u8; 32],
        )
    );
}

#[test]
fn a_token_utxo_balances_transfers_deposits_and_withdrawals() {
    let mut token = TokenUtxo::new_mut(&[
        native(&spendable(&keypair(11), MINT, 300, 1)),
        native(&spendable(&keypair(11), MINT, 200, 2)),
        Utxo::dummy(),
    ])
    .unwrap();
    let mut transfer = TokenUtxo::new_init(&owner(30), &token.asset());
    token.transfer(&mut transfer, &uint(350)).unwrap();
    let account = circuit::Bytes::constant(&[6u8; 32]);
    token.deposit(&uint(10), &account).unwrap();
    token.withdraw(&uint(5), &account).unwrap();
    let overspent = error(token.transfer(&mut transfer, &uint(156)));
    let overdrawn = error(token.withdraw(&uint(156), &account));
    let balance = balance_bytes(&token);
    let mut everything = TokenUtxo::new_init(&owner(31), &token.asset());
    token.transfer_all(&mut everything).unwrap();
    let mut deposit_only = TokenUtxo::new_init(&owner(11), &Asset::constant(&MINT.asset));
    deposit_only.deposit(&uint(25), &account).unwrap();

    assert_eq!(
        (
            balance,
            to_bytes(&token.owner().hash().unwrap()).unwrap(),
            balance_bytes(&transfer),
            balance_bytes(&deposit_only),
            (balance_bytes(&everything), balance_bytes(&token),),
            overspent,
            overdrawn,
            error(TokenUtxo::new_mut(&[
                native(&spendable(&keypair(11), MINT, 300, 1)),
                native(&spendable(&keypair(12), MINT, 1, 3)),
            ])),
            error(TokenUtxo::new_burn(&[
                Utxo::dummy(),
                native(&spendable(&keypair(11), MINT, 300, 1)),
            ])),
            error(TokenUtxo::new_mut(&[])),
        ),
        (
            bytes(155),
            owner_hash(11),
            bytes(350),
            bytes(25),
            (bytes(155), [0u8; 32]),
            "the transfer exceeds the balance".to_string(),
            "the withdrawal exceeds the balance".to_string(),
            "the inputs belong to different owners".to_string(),
            "the first input of a token utxo is a dummy".to_string(),
            "a token utxo spends at least one input".to_string(),
        )
    );
}

#[test]
fn a_token_utxo_enforces_its_rules_in_r1cs() {
    let spend = |inputs: [WalletUtxo; 2]| {
        let cs = ConstraintSystem::new_ref();
        let allocator = Allocator::R1cs(cs.clone());
        let inputs = inputs.map(|input| input.instantiate(&allocator).unwrap());
        let _token = TokenUtxo::new_mut(&inputs).unwrap();
        cs.is_satisfied().unwrap()
    };
    let dummy_with_value = {
        let cs = ConstraintSystem::new_ref();
        let allocator = Allocator::R1cs(cs.clone());
        let mut dummy = WalletUtxo::dummy(TREE_ID).unwrap();
        dummy.utxo.amount = 1_000;
        let token = TokenUtxo::new_mut(&[
            spendable(&keypair(11), MINT, 300, 1)
                .instantiate(&allocator)
                .unwrap(),
            dummy.instantiate(&allocator).unwrap(),
        ])
        .unwrap();
        token
            .balance()
            .unwrap()
            .assert_equal(&uint(300), "the dummy adds nothing to the balance")
            .unwrap();
        cs.is_satisfied().unwrap()
    };

    assert_eq!(
        (
            spend([
                spendable(&keypair(11), MINT, 300, 1),
                spendable(&keypair(11), MINT, 200, 2)
            ]),
            spend([
                spendable(&keypair(11), MINT, 300, 1),
                spendable(&keypair(12), MINT, 200, 2)
            ]),
            dummy_with_value,
        ),
        (true, false, true)
    );
}

fn natively_and_in_r1cs(
    run: impl Fn(&Allocator) -> Result<(), CircuitError>,
) -> (Result<(), String>, Result<bool, String>) {
    let native = run(&Allocator::native()).map_err(|e| e.to_string());
    let cs = ConstraintSystem::new_ref();
    let in_r1cs = run(&Allocator::R1cs(cs.clone()))
        .map_err(|e| e.to_string())
        .and_then(|()| cs.is_satisfied().map_err(|e| e.to_string()));
    (native, in_r1cs)
}

fn tokens(allocator: &Allocator, owner: u8, mint: Mint, amount: u64) -> TokenUtxo {
    TokenUtxo::new_mut(&[spendable(&keypair(owner), mint, amount, 1)
        .instantiate(allocator)
        .unwrap()])
    .unwrap()
}

fn amount(allocator: &Allocator, amount: u64) -> Uint<64> {
    amount.instantiate(allocator).unwrap()
}

#[test]
fn a_transfer_refuses_a_destination_in_another_asset() {
    let into_empty = natively_and_in_r1cs(|allocator| {
        let mut destination = TokenUtxo::new_init(&owner(30), &Asset::sol());
        tokens(allocator, 11, MINT, 50).transfer(&mut destination, &amount(allocator, 10u64))
    });
    let into_non_empty = |mint: Mint| {
        natively_and_in_r1cs(move |allocator| {
            let mut destination = tokens(allocator, 12, mint, 5);
            tokens(allocator, 11, MINT, 50).transfer(&mut destination, &amount(allocator, 10u64))
        })
    };
    let into_data = natively_and_in_r1cs(|allocator| {
        let counter_hash = to_bytes(&counter(9).hash()?)?;
        let input = with_data_hash(
            &keypair(12),
            spendable(&keypair(12), Mint::SOL, 7, 0),
            counter_hash,
        );
        let mut destination = DataUtxo::new_mut(&input.instantiate(allocator)?, &counter(9))?;
        tokens(allocator, 11, MINT, 50).transfer_all(&mut destination)
    });
    let other_asset = || {
        (
            Err("the destination holds another asset".to_string()),
            Ok(false),
        )
    };

    assert_eq!(
        (
            into_empty,
            into_non_empty(Mint::SOL),
            into_data,
            into_non_empty(MINT)
        ),
        (
            other_asset(),
            other_asset(),
            other_asset(),
            (Ok(()), Ok(true))
        )
    );
}

#[test]
fn a_burned_utxo_receives_no_transfer() {
    let burned = |allocator: &Allocator| {
        TokenUtxo::new_burn(&[spendable(&keypair(12), MINT, 5, 2)
            .instantiate(allocator)
            .unwrap()])
        .unwrap()
    };
    let refused = || {
        (
            Err("a burned utxo receives no transfer".to_string()),
            Err("a burned utxo receives no transfer".to_string()),
        )
    };

    assert_eq!(
        (
            natively_and_in_r1cs(|allocator| {
                tokens(allocator, 11, MINT, 50)
                    .transfer(&mut burned(allocator), &amount(allocator, 1u64))
            }),
            natively_and_in_r1cs(|allocator| {
                tokens(allocator, 11, MINT, 50).transfer_all(&mut burned(allocator))
            }),
        ),
        (refused(), refused())
    );
}

#[test]
fn an_overdraw_is_unsatisfied_in_r1cs() {
    let account = circuit::Bytes::constant(&[6u8; 32]);
    let transfer = |paid: u64| {
        natively_and_in_r1cs(move |allocator| {
            let mut source = tokens(allocator, 11, MINT, 50);
            let mut destination = TokenUtxo::new_init(&owner(30), &source.asset());
            source.transfer(&mut destination, &amount(allocator, paid))
        })
    };
    let withdraw = |withdrawn: u64| {
        natively_and_in_r1cs(|allocator| {
            tokens(allocator, 11, MINT, 50).withdraw(&amount(allocator, withdrawn), &account)
        })
    };

    assert_eq!(
        (transfer(50), transfer(51), withdraw(50), withdraw(51)),
        (
            (Ok(()), Ok(true)),
            (
                Err("the transfer exceeds the balance".to_string()),
                Ok(false)
            ),
            (Ok(()), Ok(true)),
            (
                Err("the withdrawal exceeds the balance".to_string()),
                Ok(false)
            ),
        )
    );
}

#[test]
fn a_field_negative_value_cannot_become_a_uint64() {
    let negative = -Field::from(20u64);

    assert_eq!(
        natively_and_in_r1cs(|allocator| {
            Uint::<64>::try_from(&negative.instantiate(allocator)?).map(|_| ())
        }),
        (
            Err("a value does not fit in 64 bits".to_string()),
            Ok(false)
        )
    );
}

#[test]
fn a_public_transfer_of_zero_is_unsatisfied_in_r1cs() {
    let account = circuit::Bytes::constant(&[6u8; 32]);
    let deposit = |deposited: u64| {
        natively_and_in_r1cs(|allocator| {
            tokens(allocator, 11, MINT, 50).deposit(&amount(allocator, deposited), &account)
        })
    };
    let withdraw = |withdrawn: u64| {
        natively_and_in_r1cs(|allocator| {
            tokens(allocator, 11, MINT, 50).withdraw(&amount(allocator, withdrawn), &account)
        })
    };
    let withdraw_all = |held: u64| {
        natively_and_in_r1cs(|allocator| {
            tokens(allocator, 11, MINT, held)
                .withdraw_all(&account)
                .map(|_| ())
        })
    };
    let refused = || {
        (
            Err("a public transfer moves a nonzero amount".to_string()),
            Ok(false),
        )
    };

    assert_eq!(
        [
            deposit(5),
            deposit(0),
            withdraw(5),
            withdraw(0),
            withdraw_all(5),
            withdraw_all(0),
        ],
        [
            (Ok(()), Ok(true)),
            refused(),
            (Ok(()), Ok(true)),
            refused(),
            (Ok(()), Ok(true)),
            refused(),
        ]
    );
}

#[test]
fn a_balance_is_range_checked_only_when_its_inputs_can_exceed_64_bits() {
    let cs = ConstraintSystem::new_ref();
    let allocator = Allocator::R1cs(cs.clone());
    let cost = |read: &dyn Fn() -> Result<Uint<64>, CircuitError>| {
        let before = cs.num_constraints();
        read().map(|_| ()).unwrap();
        cs.num_constraints() - before
    };
    let single = tokens(&allocator, 11, MINT, 50);
    let mut double = TokenUtxo::new_mut(&[
        spendable(&keypair(11), MINT, 50, 1)
            .instantiate(&allocator)
            .unwrap(),
        spendable(&keypair(11), MINT, 20, 2)
            .instantiate(&allocator)
            .unwrap(),
    ])
    .unwrap();
    let costs = (cost(&|| single.balance()), cost(&|| double.balance()));
    let mut destination = TokenUtxo::new_init(&owner(30), &double.asset());
    double
        .transfer(&mut destination, &amount(&allocator, 10))
        .unwrap();

    assert_eq!(
        (
            costs,
            cost(&|| double.balance()),
            cost(&|| destination.balance()),
            cs.is_satisfied().unwrap(),
        ),
        ((0, 65), 0, 0, true)
    );
}

#[test]
fn a_destination_built_from_the_source_asset_adds_no_asset_constraints() {
    let cs = ConstraintSystem::new_ref();
    let allocator = Allocator::R1cs(cs.clone());
    let cost = |transfer: &mut dyn FnMut() -> Result<(), CircuitError>| {
        let before = cs.num_constraints();
        transfer().unwrap();
        cs.num_constraints() - before
    };
    let mut source = tokens(&allocator, 11, MINT, 50);
    let mut shared = TokenUtxo::new_init(&owner(30), &source.asset());
    let mut separate = TokenUtxo::new_init(&owner(30), &Asset::constant(&MINT.asset));
    let paid = amount(&allocator, 10u64);
    let costs = (
        cost(&mut || source.transfer(&mut shared, &paid)),
        cost(&mut || source.transfer(&mut separate, &paid)),
        cost(&mut || source.transfer_all(&mut shared)),
        cost(&mut || shared.transfer_all(&mut separate)),
    );

    assert_eq!((costs, cs.is_satisfied().unwrap()), ((65, 67, 0, 2), true));
}
