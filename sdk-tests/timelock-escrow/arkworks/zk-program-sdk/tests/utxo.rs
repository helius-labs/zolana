use solana_address::Address;
use zk_program_sdk::{
    circuit::{
        self, constant, poseidon, zero, Asset, CircuitVar, ConstraintSystem, DataHash, DataUtxo,
        Field, TokenUtxo, Utxo,
    },
    conversion::{field_bytes, to_bytes, Allocator, ProofInput},
    RelationError,
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
    value: CircuitVar,
}

impl Default for Counter {
    fn default() -> Self {
        Self { value: zero() }
    }
}

impl DataHash for Counter {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        poseidon(&[self.value.hash()?])
    }
}

fn counter(value: u64) -> Counter {
    Counter {
        value: constant(value),
    }
}

fn error<T>(result: Result<T, RelationError>) -> String {
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
    let mut tokens = TokenUtxo::new_mut([native(&spendable(&keypair(11), MINT, 50, 1))]).unwrap();
    let funded =
        DataUtxo::<Counter>::from_output_utxo(tokens.transfer(&owner(12), constant(30u64)))
            .unwrap();
    let valueless = DataUtxo::<Counter>::new_init(&owner(12)).unwrap();
    let mut mutated = DataUtxo::new_mut(&spent, counter(9)).unwrap();
    mutated.value = constant(10u64);
    let mut burned = DataUtxo::new_burn(&spent, counter(9)).unwrap();
    let payout = burned.transfer(&owner(40), constant(7u64)).unwrap();

    assert_eq!(
        (
            (
                to_bytes(&funded.owner().hash().unwrap()).unwrap(),
                to_bytes(funded.amount()).unwrap(),
                to_bytes(&funded.asset().hash().unwrap()).unwrap(),
            ),
            (
                to_bytes(valueless.amount()).unwrap(),
                to_bytes(&valueless.asset().hash().unwrap()).unwrap(),
            ),
            to_bytes(&mutated.value).unwrap(),
            (
                to_bytes(&payout.owner().hash().unwrap()).unwrap(),
                to_bytes(payout.amount()).unwrap(),
            ),
            error(mutated.transfer(&owner(40), constant(1u64))),
            error(DataUtxo::new_mut(&spent, counter(8))),
            error(DataUtxo::new_burn(
                &native(&spendable(&keypair(12), MINT, 7, 0)),
                counter(9)
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
            "only a burned data utxo transfers its value".to_string(),
            "the input does not commit to its program state".to_string(),
            "the input does not commit to its program state".to_string(),
        )
    );
}

#[test]
fn a_token_utxo_balances_transfers_deposits_and_withdrawals() {
    let mut token = TokenUtxo::new_mut([
        native(&spendable(&keypair(11), MINT, 300, 1)),
        native(&spendable(&keypair(11), MINT, 200, 2)),
        Utxo::dummy(),
    ])
    .unwrap();
    let transfer = token.transfer(&owner(30), constant(350u64));
    let account = circuit::Bytes::constant(&[6u8; 32]);
    token.deposit(&constant(10u64), &account);
    token.withdraw(&constant(5u64), &account);
    let mut deposit_only = TokenUtxo::new_init(&owner(11), &Asset::constant(&MINT.asset));
    deposit_only.deposit(&constant(25u64), &account);

    assert_eq!(
        (
            to_bytes(token.balance()).unwrap(),
            to_bytes(&token.owner().hash().unwrap()).unwrap(),
            to_bytes(transfer.amount()).unwrap(),
            to_bytes(deposit_only.balance()).unwrap(),
            error(TokenUtxo::new_mut([
                native(&spendable(&keypair(11), MINT, 300, 1)),
                native(&spendable(&keypair(12), MINT, 1, 3)),
            ])),
            error(TokenUtxo::new_burn([
                Utxo::dummy(),
                native(&spendable(&keypair(11), MINT, 300, 1)),
            ])),
            error(TokenUtxo::new_mut([])),
        ),
        (
            bytes(155),
            owner_hash(11),
            bytes(350),
            bytes(25),
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
        let _token = TokenUtxo::new_mut(inputs).unwrap();
        cs.is_satisfied().unwrap()
    };
    let dummy_with_value = {
        let cs = ConstraintSystem::new_ref();
        let allocator = Allocator::R1cs(cs.clone());
        let mut dummy = WalletUtxo::dummy(TREE_ID).unwrap();
        dummy.utxo.amount = 1_000;
        let token = TokenUtxo::new_mut([
            spendable(&keypair(11), MINT, 300, 1)
                .instantiate(&allocator)
                .unwrap(),
            dummy.instantiate(&allocator).unwrap(),
        ])
        .unwrap();
        (
            to_bytes(token.balance()).unwrap(),
            cs.is_satisfied().unwrap(),
        )
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
        (true, false, (bytes(300), true))
    );
}
