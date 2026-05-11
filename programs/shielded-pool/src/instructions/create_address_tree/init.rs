use light_batched_merkle_tree::initialize_address_tree::InitAddressTreeAccountsInstructionData;
use zolana_interface::instruction::CreateAddressTreeData;

pub fn batched_tree_params(data: &CreateAddressTreeData) -> InitAddressTreeAccountsInstructionData {
    InitAddressTreeAccountsInstructionData {
        height: data.height as u32,
        input_queue_batch_size: data.queue_capacity as u64,
        ..Default::default()
    }
}
