#![cfg(feature = "compression")]

use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_hasher::primitives::right_align;
use zolana_interface::{
    instruction::instruction_data::transact::{TransactProof, TreeContext},
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program::{
    compression::{
        AddressSeed, CompressedAccount, CompressedAccountData, CompressedAccountError, NewAddress,
        PdaOwner, SppTransactCpi,
    },
    cpi::SppTransactAccounts,
};
use zolana_tree::{NullifierTreeInitParams, TreeAccount, TreeFeeSchedule};

const OUTPUT_TREE: [u8; 32] = [21u8; 32];
const PDA: [u8; 32] = [4u8; 32];

fn view(address: [u8; 32], owner: [u8; 32], data: Vec<u8>) -> AccountView {
    get_account_view(address, owner, false, true, false, data)
}

fn tree_data() -> Vec<u8> {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    TreeAccount::init(
        &mut bytes,
        TREE_ACCOUNT_DISCRIMINATOR,
        32,
        OUTPUT_TREE,
        5,
        NullifierTreeInitParams::default(),
        TreeFeeSchedule::at_cost(250, 5_000, 46).unwrap(),
    )
    .unwrap();
    bytes
}

/// payer, output tree, the shielded pool, the system program and the owner
/// PDA, with `output_tree` and `spp_program` replaceable.
fn transact_accounts(output_tree: AccountView, spp_program: [u8; 32]) -> Vec<AccountView> {
    vec![
        view([1u8; 32], [0u8; 32], Vec::new()),
        output_tree,
        view(spp_program, [2u8; 32], Vec::new()),
        view([0u8; 32], [3u8; 32], Vec::new()),
        view(PDA, [0u8; 32], Vec::new()),
    ]
}

fn pool_output_tree() -> AccountView {
    view(OUTPUT_TREE, SHIELDED_POOL_PROGRAM_ID, tree_data())
}

/// A state whose data hash is its count.
#[derive(borsh::BorshSerialize, Default)]
struct CountState {
    address: [u8; 32],
    count: u8,
    blinding: [u8; 32],
}

impl CompressedAccountData for CountState {
    fn data_hash(&self) -> Result<[u8; 32], ProgramError> {
        Ok(right_align(&[self.count]))
    }

    fn address_mut(&mut self) -> &mut [u8; 32] {
        &mut self.address
    }

    fn blinding_mut(&mut self) -> &mut [u8; 32] {
        &mut self.blinding
    }
}

fn cpi(owner: &PdaOwner) -> SppTransactCpi<'_> {
    let address = NewAddress::derive(owner, AddressSeed::owner(owner), 1).unwrap();
    let mut account: CompressedAccount<'_, CountState> = CompressedAccount::new_init(
        owner,
        address,
        TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        },
    );
    account.count = 11;
    SppTransactCpi::new(TransactProof {
        a: [1u8; 32],
        b: [2u8; 128],
        c: [3u8; 32],
    })
    .with_compressed_account(account)
    .unwrap()
}

#[test]
fn invoke_accepts_a_signed_owner_and_a_pool_output_tree() {
    let pda = Address::new_from_array(PDA);
    let owner = PdaOwner::new(&pda).unwrap();
    let signer_pdas = [&pda];
    let accounts = transact_accounts(pool_output_tree(), SHIELDED_POOL_PROGRAM_ID);
    let spp = SppTransactAccounts::new(&accounts, &signer_pdas).unwrap();

    assert_eq!(cpi(&owner).invoke::<8>(&spp, &[]), Ok(()));
}

#[test]
fn invoke_rejects_an_owner_it_does_not_sign_for() {
    let pda = Address::new_from_array(PDA);
    let other_owner = PdaOwner::new(&Address::new_from_array([6u8; 32])).unwrap();
    let signer_pdas = [&pda];
    let accounts = transact_accounts(pool_output_tree(), SHIELDED_POOL_PROGRAM_ID);
    let spp = SppTransactAccounts::new(&accounts, &signer_pdas).unwrap();

    assert_eq!(
        cpi(&other_owner).invoke::<8>(&spp, &[]),
        Err(CompressedAccountError::OwnerNotSigner.into())
    );
}

#[test]
fn invoke_rejects_an_output_tree_the_pool_does_not_own() {
    let pda = Address::new_from_array(PDA);
    let owner = PdaOwner::new(&pda).unwrap();
    let signer_pdas = [&pda];
    let accounts = transact_accounts(
        view(OUTPUT_TREE, [3u8; 32], tree_data()),
        SHIELDED_POOL_PROGRAM_ID,
    );
    let spp = SppTransactAccounts::new(&accounts, &signer_pdas).unwrap();

    assert_eq!(
        cpi(&owner).invoke::<8>(&spp, &[]),
        Err(CompressedAccountError::InvalidTreeAccount.into())
    );
}

#[test]
fn error_codes_are_stable() {
    use CompressedAccountError::*;

    for (error, code) in [
        (InvalidTreeAccount, 14000),
        (AccountBorrowFailed, 14001),
        (InvalidRootIndex, 14002),
        (InvalidNullifierPda, 14003),
        (StateSpent, 14004),
        (ZeroDataHash, 14005),
        (NonCanonicalAddressSeed, 14006),
        (OwnerNotSigner, 14007),
        (NoAccounts, 14008),
        (TooManyAccounts, 14009),
        (InputTreesNotContiguous, 14010),
        (ConflictingTreeContexts, 14011),
        (InvalidOutputData, 14012),
        (InvalidExternalData, 14013),
        (HashingFailed, 14014),
        (SerializationFailed, 14015),
    ] {
        assert_eq!(ProgramError::from(error), ProgramError::Custom(code));
    }
}
