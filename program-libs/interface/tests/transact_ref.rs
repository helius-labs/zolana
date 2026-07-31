use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use zolana_interface::instruction::{
    CircuitId, InputUtxo, InterfaceTransfer, MessageData, OwnerTag, TransactIxData,
    TransactIxDataRef, TransactOutput, TransactProof,
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
    for input in &view.inputs {
        black_box(input);
    }
    for transfer in &view.interface_transfers {
        black_box(transfer);
    }
    for output in &view.outputs {
        black_box(output);
    }
    for message in &view.messages {
        black_box(message);
    }
}

#[test]
fn transact_ref_decode_only_allocates_element_vectors() {
    let owned = TransactIxData {
        expiry_unix_ts: 1,
        private_tx_hash: [2; 32],
        circuit: CircuitId::ConfidentialEddsa(1, 1, 1),
        tx_viewing_pk: [3; 33],
        salt: [4; 16],
        proof: TransactProof::zeroed(),
        inputs: vec![InputUtxo {
            nullifier_hash: [5; 32],
            nullifier_tree_root_index: 6,
            utxo_tree_root_index: 7,
        }],
        interface_transfers: vec![InterfaceTransfer::SolDeposit { amount: 8 }],
        data_hash: Some([9; 32]),
        zone_data_hash: None,
        outputs: vec![TransactOutput {
            utxo_hash: [10; 32],
            owner_tag: OwnerTag::Inline([11; 32]),
            data: Some(vec![12, 13]),
        }],
        messages: vec![MessageData {
            view_tag: [14; 32],
            data: vec![15, 16],
        }],
    };
    let bytes = owned.serialize().unwrap();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let view = black_box(TransactIxDataRef::from_bytes(black_box(&bytes))).unwrap();
    COUNTING.store(false, Ordering::Relaxed);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        4,
        "one allocation for each owned element vector"
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
