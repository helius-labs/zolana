use rings_account_checks::AccountView;
use rings_merkle_tree_metadata::{
    access::AccessMetadata, fee::compute_rollover_fee, merkle_tree::MerkleTreeMetadata,
    rollover::RolloverMetadata, TreeType,
};
use solana_address::Address as Pubkey;

use crate::{
    constants::{
        DEFAULT_ADDRESS_BATCH_ROOT_HISTORY_LEN, DEFAULT_ADDRESS_BATCH_SIZE,
        DEFAULT_ADDRESS_ZKP_BATCH_SIZE, DEFAULT_BATCH_ADDRESS_TREE_HEIGHT,
        NULLIFIER_TREE_INIT_ROOT_40,
    },
    errors::BatchedMerkleTreeError,
    merkle_tree::{get_merkle_tree_account_size, BatchedMerkleTreeAccount},
    rent::check_account_balance_is_rent_exempt,
    zero_copy::TreeAccountLayout,
    BorshDeserialize, BorshSerialize,
};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InitAddressTreeAccountsInstructionData {
    pub index: u64,
    pub program_owner: Option<Pubkey>,
    pub forester: Option<Pubkey>,
    pub input_queue_batch_size: u64,
    pub input_queue_zkp_batch_size: u64,
    pub root_history_capacity: u32,
    pub network_fee: Option<u64>,
    pub rollover_threshold: Option<u64>,
    pub close_threshold: Option<u64>,
    pub height: u32,
}

impl BorshSerialize for InitAddressTreeAccountsInstructionData {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.index.serialize(writer)?;
        crate::serialize_option_address(&self.program_owner, writer)?;
        crate::serialize_option_address(&self.forester, writer)?;
        self.input_queue_batch_size.serialize(writer)?;
        self.input_queue_zkp_batch_size.serialize(writer)?;
        self.root_history_capacity.serialize(writer)?;
        self.network_fee.serialize(writer)?;
        self.rollover_threshold.serialize(writer)?;
        self.close_threshold.serialize(writer)?;
        self.height.serialize(writer)
    }
}

impl BorshDeserialize for InitAddressTreeAccountsInstructionData {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self {
            index: BorshDeserialize::deserialize_reader(reader)?,
            program_owner: crate::deserialize_option_address(reader)?,
            forester: crate::deserialize_option_address(reader)?,
            input_queue_batch_size: BorshDeserialize::deserialize_reader(reader)?,
            input_queue_zkp_batch_size: BorshDeserialize::deserialize_reader(reader)?,
            root_history_capacity: BorshDeserialize::deserialize_reader(reader)?,
            network_fee: BorshDeserialize::deserialize_reader(reader)?,
            rollover_threshold: BorshDeserialize::deserialize_reader(reader)?,
            close_threshold: BorshDeserialize::deserialize_reader(reader)?,
            height: BorshDeserialize::deserialize_reader(reader)?,
        })
    }
}

impl Default for InitAddressTreeAccountsInstructionData {
    fn default() -> Self {
        Self {
            index: 0,
            program_owner: None,
            forester: None,
            input_queue_batch_size: DEFAULT_ADDRESS_BATCH_SIZE,
            input_queue_zkp_batch_size: DEFAULT_ADDRESS_ZKP_BATCH_SIZE,
            height: DEFAULT_BATCH_ADDRESS_TREE_HEIGHT,
            root_history_capacity: DEFAULT_ADDRESS_BATCH_ROOT_HISTORY_LEN,
            network_fee: Some(10000),
            rollover_threshold: Some(95),
            close_threshold: None,
        }
    }
}

/// Initializes a batched address Merkle tree account.
/// 1. Check rent exemption and that accounts are initialized with the correct size.
/// 2. Initialized the address Merkle tree account.
pub fn init_batched_address_merkle_tree_from_account_info(
    params: InitAddressTreeAccountsInstructionData,
    owner: Pubkey,
    mt_account_info: &mut AccountView,
) -> Result<(), BatchedMerkleTreeError> {
    init_batched_indexed_merkle_tree_from_account_info(params, owner, mt_account_info, None)
}

/// Initializes a batched nullifier Merkle tree account.
///
/// A nullifier tree is an indexed Merkle tree whose values are full BN254 field
/// elements rather than 248-bit addresses, so it is seeded with the BN254 `p-1`
/// sentinel ([`NULLIFIER_TREE_INIT_ROOT_40`]) instead of the address sentinel.
/// It otherwise reuses the address-tree account layout and parameters.
pub fn init_batched_nullifier_merkle_tree_from_account_info(
    params: InitAddressTreeAccountsInstructionData,
    owner: Pubkey,
    mt_account_info: &mut AccountView,
) -> Result<(), BatchedMerkleTreeError> {
    init_batched_indexed_merkle_tree_from_account_info(
        params,
        owner,
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
    owner: Pubkey,
    mt_account_info: &mut AccountView,
    address_init_root: Option<[u8; 32]>,
) -> Result<(), BatchedMerkleTreeError> {
    // 1. Check rent exemption and that accounts are initialized with the correct size.
    let mt_account_size = get_merkle_tree_account_size::<
        { crate::constants::ADDRESS_TREE_DEFAULT_RH },
        { crate::constants::ADDRESS_TREE_DEFAULT_NUM_ITERS },
        { crate::constants::ADDRESS_TREE_DEFAULT_BLOOM },
        { crate::constants::ADDRESS_TREE_DEFAULT_ZKP },
    >();
    let merkle_tree_rent = check_account_balance_is_rent_exempt(mt_account_info, mt_account_size)?;
    let mt_pubkey = *mt_account_info.address();
    // 2. Initialize the indexed Merkle tree account.
    let mt_data = &mut mt_account_info.try_borrow_mut()?;
    init_batched_indexed_merkle_tree_account::<
        { crate::constants::ADDRESS_TREE_DEFAULT_RH },
        { crate::constants::ADDRESS_TREE_DEFAULT_NUM_ITERS },
        { crate::constants::ADDRESS_TREE_DEFAULT_BLOOM },
        { crate::constants::ADDRESS_TREE_DEFAULT_ZKP },
    >(
        owner,
        params,
        mt_data,
        merkle_tree_rent,
        mt_pubkey,
        address_init_root,
    )?;
    Ok(())
}

pub fn init_batched_address_merkle_tree_account<
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
>(
    owner: Pubkey,
    params: InitAddressTreeAccountsInstructionData,
    mt_account_data: &mut [u8],
    merkle_tree_rent: u64,
    pubkey: Pubkey,
) -> Result<BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError> {
    init_batched_indexed_merkle_tree_account(
        owner,
        params,
        mt_account_data,
        merkle_tree_rent,
        pubkey,
        None,
    )
}

/// Initializes a batched nullifier Merkle tree account into `mt_account_data`,
/// seeding it with the BN254 `p-1` sentinel root ([`NULLIFIER_TREE_INIT_ROOT_40`]).
pub fn init_batched_nullifier_merkle_tree_account<
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
>(
    owner: Pubkey,
    params: InitAddressTreeAccountsInstructionData,
    mt_account_data: &mut [u8],
    merkle_tree_rent: u64,
    pubkey: Pubkey,
) -> Result<BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError> {
    init_batched_indexed_merkle_tree_account(
        owner,
        params,
        mt_account_data,
        merkle_tree_rent,
        pubkey,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
}

/// Shared core that initializes an indexed (address/nullifier) Merkle tree
/// account. `address_init_root` selects the sentinel root pushed into root
/// history: `None` uses the default address sentinel, `Some` overrides it.
fn init_batched_indexed_merkle_tree_account<
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
>(
    owner: Pubkey,
    params: InitAddressTreeAccountsInstructionData,
    mt_account_data: &mut [u8],
    merkle_tree_rent: u64,
    pubkey: Pubkey,
    address_init_root: Option<[u8; 32]>,
) -> Result<BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError> {
    let metadata = indexed_merkle_tree_metadata(owner, params, merkle_tree_rent)?;
    BatchedMerkleTreeAccount::init(
        mt_account_data,
        &pubkey,
        metadata,
        params.root_history_capacity,
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
pub fn init_batched_nullifier_merkle_tree_into_layout<
    const RH: usize,
    const NUM_ITERS: usize,
    const BLOOM: usize,
    const ZKP: usize,
>(
    owner: Pubkey,
    params: InitAddressTreeAccountsInstructionData,
    layout: &mut TreeAccountLayout<RH, NUM_ITERS, BLOOM, ZKP>,
    merkle_tree_rent: u64,
    pubkey: Pubkey,
) -> Result<BatchedMerkleTreeAccount<'_, RH, NUM_ITERS, BLOOM, ZKP>, BatchedMerkleTreeError> {
    let metadata = indexed_merkle_tree_metadata(owner, params, merkle_tree_rent)?;
    BatchedMerkleTreeAccount::init_from_layout(
        layout,
        &pubkey,
        metadata,
        params.root_history_capacity,
        params.input_queue_batch_size,
        params.input_queue_zkp_batch_size,
        params.height,
        TreeType::AddressV2,
        Some(NULLIFIER_TREE_INIT_ROOT_40),
    )
}

fn indexed_merkle_tree_metadata(
    owner: Pubkey,
    params: InitAddressTreeAccountsInstructionData,
    merkle_tree_rent: u64,
) -> Result<MerkleTreeMetadata, BatchedMerkleTreeError> {
    let height = params.height;

    let rollover_fee = match params.rollover_threshold {
        Some(rollover_threshold) => {
            let rent = merkle_tree_rent;
            compute_rollover_fee(rollover_threshold, height, rent)?
        }
        None => 0,
    };
    #[cfg(feature = "log")]
    solana_msg::msg!("rollover fee {}", rollover_fee);
    #[cfg(feature = "log")]
    solana_msg::msg!("rollover threshold {:?}", params.rollover_threshold);

    Ok(MerkleTreeMetadata {
        next_merkle_tree: Pubkey::default(),
        access_metadata: AccessMetadata::new(owner, params.program_owner, params.forester),
        rollover_metadata: RolloverMetadata::new(
            params.index,
            rollover_fee,
            params.rollover_threshold,
            params.network_fee.unwrap_or_default(),
            params.close_threshold,
            None,
        ),
        associated_queue: Pubkey::default(),
    })
}

/// Only used for testing. For production use the default config.
pub fn validate_batched_address_tree_params(params: InitAddressTreeAccountsInstructionData) {
    assert!(params.input_queue_batch_size > 0);
    assert_eq!(
        params.input_queue_batch_size % params.input_queue_zkp_batch_size,
        0,
        "Input queue batch size must divisible by input_queue_zkp_batch_size."
    );
    assert!(
        match_circuit_size(params.input_queue_zkp_batch_size),
        "Zkp batch size not supported. Supported: 10, 250"
    );

    assert!(params.root_history_capacity > 0);
    assert!(params.input_queue_batch_size > 0);

    // Validate root_history_capacity is sufficient for input operations
    // (address trees only have input queues, no output queues)
    let required_capacity = params.input_queue_batch_size / params.input_queue_zkp_batch_size;
    assert!(
        params.root_history_capacity >= required_capacity as u32,
        "root_history_capacity ({}) must be >= {} (input_queue_batch_size / input_queue_zkp_batch_size)",
        params.root_history_capacity,
        required_capacity
    );

    assert_eq!(params.close_threshold, None);
    assert_eq!(params.height, DEFAULT_BATCH_ADDRESS_TREE_HEIGHT);
}
/// Only 10 and 250 are supported.
pub fn match_circuit_size(size: u64) -> bool {
    matches!(size, 10 | 250)
}
pub fn get_address_merkle_tree_account_size() -> usize {
    get_merkle_tree_account_size::<
        { crate::constants::ADDRESS_TREE_DEFAULT_RH },
        { crate::constants::ADDRESS_TREE_DEFAULT_NUM_ITERS },
        { crate::constants::ADDRESS_TREE_DEFAULT_BLOOM },
        { crate::constants::ADDRESS_TREE_DEFAULT_ZKP },
    >()
}

#[cfg(feature = "test-only")]
pub mod test_utils {
    pub use super::InitAddressTreeAccountsInstructionData;
    use crate::constants::{
        DEFAULT_ADDRESS_ZKP_BATCH_SIZE, DEFAULT_BATCH_ROOT_HISTORY_LEN, TEST_DEFAULT_BATCH_SIZE,
        TEST_DEFAULT_ZKP_BATCH_SIZE,
    };

    impl InitAddressTreeAccountsInstructionData {
        pub fn test_default() -> Self {
            Self {
                index: 0,
                program_owner: None,
                forester: None,
                input_queue_batch_size: TEST_DEFAULT_BATCH_SIZE,
                input_queue_zkp_batch_size: TEST_DEFAULT_ZKP_BATCH_SIZE,
                height: 40,
                root_history_capacity: DEFAULT_BATCH_ROOT_HISTORY_LEN,
                network_fee: Some(10000),
                rollover_threshold: Some(95),
                close_threshold: None,
            }
        }

        pub fn e2e_test_default() -> Self {
            Self {
                index: 0,
                program_owner: None,
                forester: None,
                input_queue_batch_size: 500,
                input_queue_zkp_batch_size: TEST_DEFAULT_ZKP_BATCH_SIZE,
                height: 40,
                root_history_capacity: DEFAULT_BATCH_ROOT_HISTORY_LEN,
                network_fee: Some(10000),
                rollover_threshold: Some(95),
                close_threshold: None,
            }
        }
        pub fn testnet_default() -> Self {
            Self {
                index: 0,
                program_owner: None,
                forester: None,
                input_queue_batch_size: 15000,
                input_queue_zkp_batch_size: DEFAULT_ADDRESS_ZKP_BATCH_SIZE,
                height: 40,
                root_history_capacity: DEFAULT_BATCH_ROOT_HISTORY_LEN,
                network_fee: Some(10000),
                rollover_threshold: Some(95),
                close_threshold: None,
            }
        }
    }
}

#[test]
fn test_validate_batched_address_tree_params() {
    let params = InitAddressTreeAccountsInstructionData::default();
    validate_batched_address_tree_params(params);
}

#[test]
#[should_panic = "Input queue batch size must divisible by input_queue_zkp_batch_size."]
fn test_input_queue_batch_size_not_divisible_by_zkp_batch_size() {
    let params = InitAddressTreeAccountsInstructionData {
        input_queue_batch_size: 11,
        input_queue_zkp_batch_size: 10, // Not divisible
        ..InitAddressTreeAccountsInstructionData::default()
    };
    validate_batched_address_tree_params(params);
}

#[test]
#[should_panic = "Input queue batch size must divisible by input_queue_zkp_batch_size."]
fn test_invalid_zkp_batch_size() {
    let params = InitAddressTreeAccountsInstructionData {
        input_queue_zkp_batch_size: 7, // Unsupported size
        ..InitAddressTreeAccountsInstructionData::default()
    };
    validate_batched_address_tree_params(params);
}

#[test]
#[should_panic]
fn test_root_history_capacity_zero() {
    let params = InitAddressTreeAccountsInstructionData {
        root_history_capacity: 0,
        ..InitAddressTreeAccountsInstructionData::default()
    };
    validate_batched_address_tree_params(params);
}

#[test]
#[should_panic]
fn test_close_threshold_not_none() {
    let params = InitAddressTreeAccountsInstructionData {
        close_threshold: Some(10),
        ..InitAddressTreeAccountsInstructionData::default()
    };
    validate_batched_address_tree_params(params);
}

#[test]
#[should_panic]
fn test_height_not_40() {
    let params = InitAddressTreeAccountsInstructionData {
        height: 30,
        ..InitAddressTreeAccountsInstructionData::default()
    };
    validate_batched_address_tree_params(params);
}

#[test]
fn test_validate_root_history_capacity_address_tree() {
    // Test with valid params (default should pass)
    let params = InitAddressTreeAccountsInstructionData::default();
    validate_batched_address_tree_params(params); // Should not panic
}

#[test]
#[should_panic(expected = "root_history_capacity")]
fn test_validate_root_history_capacity_insufficient_address_tree() {
    let params = InitAddressTreeAccountsInstructionData {
        root_history_capacity: 1, // Much too small
        input_queue_batch_size: 1000,
        input_queue_zkp_batch_size: 10,
        // Required: 1000/10 = 100, but we set only 1
        ..Default::default()
    };
    validate_batched_address_tree_params(params); // Should panic
}

#[test]
fn test_init_indexed_tree_init_roots() {
    use crate::constants::{ADDRESS_TREE_INIT_ROOT_40, NULLIFIER_TREE_INIT_ROOT_40};

    let params = InitAddressTreeAccountsInstructionData::default();
    let rent = 1_000_000_000;

    // Nullifier tree is seeded with the BN254 p-1 sentinel root.
    let mut nullifier_data = vec![0u8; get_address_merkle_tree_account_size()];
    let nullifier_account = init_batched_nullifier_merkle_tree_account::<
        { crate::constants::ADDRESS_TREE_DEFAULT_RH },
        { crate::constants::ADDRESS_TREE_DEFAULT_NUM_ITERS },
        { crate::constants::ADDRESS_TREE_DEFAULT_BLOOM },
        { crate::constants::ADDRESS_TREE_DEFAULT_ZKP },
    >(
        Pubkey::new_unique(),
        params,
        &mut nullifier_data,
        rent,
        Pubkey::new_unique(),
    )
    .unwrap();
    assert_eq!(
        *nullifier_account.layout.root_history.data.first().unwrap(),
        NULLIFIER_TREE_INIT_ROOT_40
    );
    assert_eq!(nullifier_account.next_index, 1);

    // Address tree keeps the default address sentinel root.
    let mut address_data = vec![0u8; get_address_merkle_tree_account_size()];
    let address_account = init_batched_address_merkle_tree_account::<
        { crate::constants::ADDRESS_TREE_DEFAULT_RH },
        { crate::constants::ADDRESS_TREE_DEFAULT_NUM_ITERS },
        { crate::constants::ADDRESS_TREE_DEFAULT_BLOOM },
        { crate::constants::ADDRESS_TREE_DEFAULT_ZKP },
    >(
        Pubkey::new_unique(),
        params,
        &mut address_data,
        rent,
        Pubkey::new_unique(),
    )
    .unwrap();
    assert_eq!(
        *address_account.layout.root_history.data.first().unwrap(),
        ADDRESS_TREE_INIT_ROOT_40
    );
    assert_eq!(address_account.next_index, 1);

    // The two indexed trees differ only by their sentinel root.
    assert_ne!(NULLIFIER_TREE_INIT_ROOT_40, ADDRESS_TREE_INIT_ROOT_40);
}
