use solana_address::Address as Pubkey;
use zolana_account_checks::AccountView;

use crate::{
    constants::{
        ADDRESS_TREE_DEFAULT_RH, ADDRESS_TREE_DEFAULT_ZKP, DEFAULT_ADDRESS_BATCH_SIZE,
        DEFAULT_ADDRESS_ZKP_BATCH_SIZE, DEFAULT_BATCH_ADDRESS_TREE_HEIGHT,
        NULLIFIER_TREE_INIT_ROOT_40,
    },
    errors::BatchedMerkleTreeError,
    merkle_tree::{get_merkle_tree_account_size, BatchedMerkleTreeAccount},
    merkle_tree_metadata::TreeType,
    rent::check_account_balance_is_rent_exempt,
    zero_copy::TreeAccountLayout,
    BorshDeserialize, BorshSerialize,
};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct InitAddressTreeAccountsInstructionData {
    pub input_queue_batch_size: u64,
    pub input_queue_zkp_batch_size: u64,
    pub height: u32,
}

impl Default for InitAddressTreeAccountsInstructionData {
    fn default() -> Self {
        Self {
            input_queue_batch_size: DEFAULT_ADDRESS_BATCH_SIZE,
            input_queue_zkp_batch_size: DEFAULT_ADDRESS_ZKP_BATCH_SIZE,
            height: DEFAULT_BATCH_ADDRESS_TREE_HEIGHT,
        }
    }
}

/// Initializes a batched address Merkle tree account.
/// 1. Check rent exemption and that accounts are initialized with the correct size.
/// 2. Initialized the address Merkle tree account.
pub fn init_batched_address_merkle_tree_from_account_info(
    params: InitAddressTreeAccountsInstructionData,
    mt_account_info: &mut AccountView,
) -> Result<(), BatchedMerkleTreeError> {
    init_batched_indexed_merkle_tree_from_account_info(params, mt_account_info, None)
}

/// Initializes a batched nullifier Merkle tree account.
///
/// A nullifier tree is an indexed Merkle tree whose values are full BN254 field
/// elements rather than 248-bit addresses, so it is seeded with the BN254 `p-1`
/// sentinel ([`NULLIFIER_TREE_INIT_ROOT_40`]) instead of the address sentinel.
/// It otherwise reuses the address-tree account layout and parameters.
pub fn init_batched_nullifier_merkle_tree_from_account_info(
    params: InitAddressTreeAccountsInstructionData,
    mt_account_info: &mut AccountView,
) -> Result<(), BatchedMerkleTreeError> {
    init_batched_indexed_merkle_tree_from_account_info(
        params,
        mt_account_info,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
}

/// Shared init path for indexed (address/nullifier) Merkle tree accounts.
/// `address_init_root` selects the sentinel root: `None` for the default
/// address sentinel, `Some` for a custom sentinel (e.g. nullifier).
/// 1. Check rent exemption and that accounts are initialized with the correct size.
/// 2. Initialize the indexed Merkle tree account.
fn init_batched_indexed_merkle_tree_from_account_info(
    params: InitAddressTreeAccountsInstructionData,
    mt_account_info: &mut AccountView,
    address_init_root: Option<[u8; 32]>,
) -> Result<(), BatchedMerkleTreeError> {
    // 1. Check rent exemption and that accounts are initialized with the correct size.
    let mt_account_size =
        get_merkle_tree_account_size::<ADDRESS_TREE_DEFAULT_RH, ADDRESS_TREE_DEFAULT_ZKP>();
    check_account_balance_is_rent_exempt(mt_account_info, mt_account_size)?;
    let mt_pubkey = *mt_account_info.address();
    // 2. Initialize the indexed Merkle tree account.
    let mt_data = &mut mt_account_info.try_borrow_mut()?;
    init_batched_indexed_merkle_tree_account::<ADDRESS_TREE_DEFAULT_RH, ADDRESS_TREE_DEFAULT_ZKP>(
        params,
        mt_data,
        mt_pubkey,
        address_init_root,
    )?;
    Ok(())
}

pub fn init_batched_address_merkle_tree_account<const RH: usize, const ZKP: usize>(
    params: InitAddressTreeAccountsInstructionData,
    mt_account_data: &mut [u8],
    pubkey: Pubkey,
) -> Result<BatchedMerkleTreeAccount<'_, RH, ZKP>, BatchedMerkleTreeError> {
    init_batched_indexed_merkle_tree_account(params, mt_account_data, pubkey, None)
}

/// Initializes a batched nullifier Merkle tree account into `mt_account_data`,
/// seeding it with the BN254 `p-1` sentinel root ([`NULLIFIER_TREE_INIT_ROOT_40`]).
pub fn init_batched_nullifier_merkle_tree_account<const RH: usize, const ZKP: usize>(
    params: InitAddressTreeAccountsInstructionData,
    mt_account_data: &mut [u8],
    pubkey: Pubkey,
) -> Result<BatchedMerkleTreeAccount<'_, RH, ZKP>, BatchedMerkleTreeError> {
    init_batched_indexed_merkle_tree_account(
        params,
        mt_account_data,
        pubkey,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
}

/// Shared core that initializes an indexed (address/nullifier) Merkle tree
/// account. `address_init_root` selects the sentinel root pushed into root
/// history: `None` uses the default address sentinel, `Some` overrides it.
fn init_batched_indexed_merkle_tree_account<const RH: usize, const ZKP: usize>(
    params: InitAddressTreeAccountsInstructionData,
    mt_account_data: &mut [u8],
    pubkey: Pubkey,
    address_init_root: Option<[u8; 32]>,
) -> Result<BatchedMerkleTreeAccount<'_, RH, ZKP>, BatchedMerkleTreeError> {
    BatchedMerkleTreeAccount::init(
        mt_account_data,
        &pubkey,
        params.input_queue_batch_size,
        params.input_queue_zkp_batch_size,
        params.height,
        TreeType::AddressV2,
        address_init_root,
    )
}

/// Initializes a batched nullifier Merkle tree directly into a typed
/// [`TreeAccountLayout`], seeding it with the BN254 `p-1` sentinel root
/// ([`NULLIFIER_TREE_INIT_ROOT_40`]). Used by callers that hold a typed layout
/// view (e.g. a combined account layout) instead of a raw byte slice.
pub fn init_batched_nullifier_merkle_tree_into_layout<const RH: usize, const ZKP: usize>(
    params: InitAddressTreeAccountsInstructionData,
    layout: &mut TreeAccountLayout<RH, ZKP>,
    pubkey: Pubkey,
) -> Result<BatchedMerkleTreeAccount<'_, RH, ZKP>, BatchedMerkleTreeError> {
    BatchedMerkleTreeAccount::init_from_layout(
        layout,
        &pubkey,
        params.input_queue_batch_size,
        params.input_queue_zkp_batch_size,
        params.height,
        TreeType::AddressV2,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
}

/// Only 10 and 250 are supported.
pub fn match_circuit_size(size: u64) -> bool {
    matches!(size, 10 | 250)
}

#[cfg(feature = "test-only")]
pub mod test_utils {
    pub use super::InitAddressTreeAccountsInstructionData;
    use crate::constants::{TEST_DEFAULT_BATCH_SIZE, TEST_DEFAULT_ZKP_BATCH_SIZE};

    impl InitAddressTreeAccountsInstructionData {
        pub fn test_default() -> Self {
            Self {
                input_queue_batch_size: TEST_DEFAULT_BATCH_SIZE,
                input_queue_zkp_batch_size: TEST_DEFAULT_ZKP_BATCH_SIZE,
                height: 40,
            }
        }
    }
}

#[test]
fn test_instruction_data_omits_root_history_capacity() {
    let params = InitAddressTreeAccountsInstructionData::default();
    let mut encoded = Vec::new();
    params.serialize(&mut encoded).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(&params.input_queue_batch_size.to_le_bytes());
    expected.extend_from_slice(&params.input_queue_zkp_batch_size.to_le_bytes());
    expected.extend_from_slice(&params.height.to_le_bytes());
    assert_eq!(encoded, expected);
}

#[test]
fn test_init_indexed_tree_init_roots() {
    use crate::constants::{ADDRESS_TREE_INIT_ROOT_40, NULLIFIER_TREE_INIT_ROOT_40};

    let params = InitAddressTreeAccountsInstructionData::default();
    let account_size =
        get_merkle_tree_account_size::<ADDRESS_TREE_DEFAULT_RH, ADDRESS_TREE_DEFAULT_ZKP>();

    // Nullifier tree is seeded with the BN254 p-1 sentinel root.
    let mut nullifier_data = vec![0u8; account_size];
    let nullifier_account = init_batched_nullifier_merkle_tree_account::<
        ADDRESS_TREE_DEFAULT_RH,
        ADDRESS_TREE_DEFAULT_ZKP,
    >(params, &mut nullifier_data, Pubkey::new_unique())
    .unwrap();
    assert_eq!(
        *nullifier_account.layout.root_history.data.first().unwrap(),
        NULLIFIER_TREE_INIT_ROOT_40
    );
    assert_eq!(
        nullifier_account.root_history_capacity,
        (params.input_queue_batch_size / params.input_queue_zkp_batch_size) as u32
    );
    assert_eq!(nullifier_account.next_index, 1);

    // Address tree keeps the default address sentinel root.
    let mut address_data = vec![0u8; account_size];
    let address_account = init_batched_address_merkle_tree_account::<
        ADDRESS_TREE_DEFAULT_RH,
        ADDRESS_TREE_DEFAULT_ZKP,
    >(params, &mut address_data, Pubkey::new_unique())
    .unwrap();
    assert_eq!(
        *address_account.layout.root_history.data.first().unwrap(),
        ADDRESS_TREE_INIT_ROOT_40
    );
    assert_eq!(address_account.next_index, 1);

    // The two indexed trees differ only by their sentinel root.
    assert_ne!(NULLIFIER_TREE_INIT_ROOT_40, ADDRESS_TREE_INIT_ROOT_40);
}
