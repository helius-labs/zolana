use core::mem::size_of;

use zolana_tree::nullifier_tree::{error::NullifierTreeError, layout::NullifierTreeLayout};

pub fn init_tree_account_data<const ZKP_BATCHES: usize>(
    account_data: &mut [u8],
    input_queue_batch_size: u64,
    input_queue_zkp_batch_size: u64,
    height: u32,
) -> Result<&mut NullifierTreeLayout<ZKP_BATCHES>, NullifierTreeError> {
    let layout = cast_tree_account_data(account_data)?;
    layout.init(input_queue_batch_size, input_queue_zkp_batch_size, height)?;
    Ok(layout)
}

pub fn load_tree_account_data<const ZKP_BATCHES: usize>(
    account_data: &mut [u8],
) -> Result<&mut NullifierTreeLayout<ZKP_BATCHES>, NullifierTreeError> {
    let layout = cast_tree_account_data::<ZKP_BATCHES>(account_data)?;
    layout.validate()?;
    Ok(layout)
}

fn cast_tree_account_data<const ZKP_BATCHES: usize>(
    account_data: &mut [u8],
) -> Result<&mut NullifierTreeLayout<ZKP_BATCHES>, NullifierTreeError> {
    if account_data.len() != size_of::<NullifierTreeLayout<ZKP_BATCHES>>() {
        return Err(NullifierTreeError::InvalidAccountSize);
    }
    wincode::deserialize_mut(account_data).map_err(|_| NullifierTreeError::InvalidAccountSize)
}
