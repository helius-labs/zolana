use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use zolana_interface::instruction::{
    instruction_data::transact::hash_external_data, CircuitId, InputUtxo, InterfaceTransfer,
    MessageData, OwnerTag, TransactIxData, TransactIxDataRef, TransactOutput, TransactProof,
};

struct CountingAllocator;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn consume_ref(view: &TransactIxDataRef<'_>) {
    for input in view.inputs.try_iter() {
        black_box(input.unwrap());
    }
    for transfer in view.interface_transfers.try_iter() {
        black_box(transfer.unwrap());
    }
    for output in view.outputs.try_iter() {
        black_box(output.unwrap());
    }
    for message in view.messages.try_iter() {
        black_box(message.unwrap());
    }
}

fn sample_ix_data() -> TransactIxData {
    TransactIxData {
        expiry_unix_ts: 1,
        tx_viewing_pk: [3; 33],
        salt: [4; 16],
        interface_transfers: vec![InterfaceTransfer::SolDeposit { amount: 8 }],
        outputs: vec![TransactOutput {
            utxo_hash: [10; 32],
            owner_tag: OwnerTag::Inline([11; 32]),
            data: Some(vec![12, 13]),
        }],
        messages: vec![MessageData {
            view_tag: [14; 32],
            data: vec![15, 16],
        }],
        data_hash: Some([9; 32]),
        ring_data_hash: None,
        circuit: CircuitId::ConfidentialEddsa(1, 1, 1),
        proof: TransactProof::zeroed(),
        private_tx_hash: [2; 32],
        inputs: vec![InputUtxo {
            nullifier_hash: [5; 32],
            nullifier_tree_root_index: 6,
            utxo_tree_root_index: 7,
        }],
    }
}

#[test]
fn transact_ref_decode_and_hash_do_not_copy_payloads() {
    let owned = sample_ix_data();
    let bytes = owned.serialize().unwrap();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let (view, external_data_prefix) = black_box(
        TransactIxDataRef::parse_with_external_data_prefix(black_box(&bytes)),
    )
    .unwrap();
    COUNTING.store(false, Ordering::Relaxed);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "parsing instruction data must not allocate"
    );

    let addresses = [[8u8; 32], [9u8; 32]];
    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let digest = hash_external_data(
        0,
        external_data_prefix,
        &[2u8; 32],
        &[3u8; 32],
        addresses.iter(),
    )
    .unwrap();
    COUNTING.store(false, Ordering::Relaxed);
    black_box(digest);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "hashing a borrowed instruction prefix must not allocate a preimage buffer"
    );

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    consume_ref(&view);
    COUNTING.store(false, Ordering::Relaxed);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "iterating borrowed views must not allocate"
    );
}
