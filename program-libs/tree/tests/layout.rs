use core::mem::{offset_of, size_of};

use zolana_tree::{
    nullifier_tree::{
        batch::Batch,
        constants::NULLIFIER_TREE_ZKP_BATCHES,
        layout::{NullifierTreeLayout, RootHistory},
    },
    NullifierTreeInitParams, TreeAccount, TreeAccountLayout, TreeError, TreeFeeSchedule,
    UtxoTreeLayout, TREE_RESERVED_BYTES, UTXO_TREE_HEIGHT,
};

type Layout = TreeAccountLayout<UTXO_TREE_HEIGHT, NULLIFIER_TREE_ZKP_BATCHES>;
type UtxoLayout = UtxoTreeLayout<UTXO_TREE_HEIGHT>;
type NullifierLayout = NullifierTreeLayout<NULLIFIER_TREE_ZKP_BATCHES>;
type NullifierRoots = RootHistory<NULLIFIER_TREE_ZKP_BATCHES>;
type NullifierBatch = Batch<NULLIFIER_TREE_ZKP_BATCHES>;

#[test]
fn account_layout_is_pinned() {
    assert_eq!(size_of::<Layout>(), 40_080);
    assert_eq!(TreeAccount::account_size(), 40_080);
    assert_eq!(offset_of!(Layout, tree_id), 2);
    assert_eq!(offset_of!(Layout, fees), 8);
    assert_eq!(offset_of!(Layout, fee_balance), 32);
    assert_eq!(offset_of!(Layout, _reserved), 40);
    assert_eq!(offset_of!(Layout, utxo), 72);
    assert_eq!(TreeAccount::state_root_offset(), 80);
    assert_eq!(offset_of!(Layout, nullifier), 17_152);

    assert_eq!(size_of::<UtxoLayout>(), 17_080);
    assert_eq!(offset_of!(UtxoLayout, next_index), 0);
    assert_eq!(offset_of!(UtxoLayout, root), 8);
    assert_eq!(offset_of!(UtxoLayout, root_history_cursor), 40);
    assert_eq!(offset_of!(UtxoLayout, root_history_len), 42);
    assert_eq!(offset_of!(UtxoLayout, root_history_capacity), 44);
    assert_eq!(offset_of!(UtxoLayout, subtrees_len), 46);
    assert_eq!(offset_of!(UtxoLayout, _padding), 47);
    assert_eq!(offset_of!(UtxoLayout, last_update_slot), 48);
    assert_eq!(offset_of!(UtxoLayout, subtrees), 56);
    assert_eq!(offset_of!(UtxoLayout, root_history), 1_080);

    assert_eq!(size_of::<NullifierLayout>(), 22_928);
    assert_eq!(offset_of!(NullifierLayout, root_history), 72);
    assert_eq!(offset_of!(NullifierRoots, current_index), 0);
    assert_eq!(offset_of!(NullifierRoots, roots), 8);
    assert_eq!(offset_of!(NullifierLayout, batches), 3_280);
    assert_eq!(size_of::<NullifierBatch>(), 9_824);
    assert_eq!(offset_of!(NullifierBatch, start_index), 48);
}

/// The previous layout had no pending-value buffers and was 39,952 bytes. Such
/// an account must not load as the current layout.
#[test]
fn previous_layout_size_is_rejected() {
    let mut bytes = vec![0u8; 39_952];
    assert!(matches!(
        TreeAccount::from_bytes(&mut bytes, [2u8; 32]),
        Err(TreeError::Deserialize)
    ));
    assert!(matches!(
        TreeAccount::init(
            &mut bytes,
            7,
            UTXO_TREE_HEIGHT as u8,
            [2u8; 32],
            1,
            NullifierTreeInitParams::default(),
            TreeFeeSchedule {
                fee_per_nullifier: 0,
                append_reimbursement: 0,
                close_reimbursement: 0,
            },
        ),
        Err(TreeError::InvalidBufferSize)
    ));
}

#[test]
fn init_zeroes_reserved_header() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    {
        let layout: &mut Layout = wincode::deserialize_mut(&mut bytes).expect("cast layout");
        layout._reserved.fill(0xa5);
        layout.fee_balance = 0xa5a5;
    }
    let fees = TreeFeeSchedule {
        fee_per_nullifier: 190,
        append_reimbursement: 5_000,
        close_reimbursement: 46,
    };

    {
        let tree = TreeAccount::init(
            &mut bytes,
            7,
            UTXO_TREE_HEIGHT as u8,
            [2u8; 32],
            0x0102,
            NullifierTreeInitParams::default(),
            fees,
        )
        .expect("initialize tree");
        assert_eq!(tree.tree_id(), 0x0102);
        assert_eq!(tree.fees(), fees);
        assert_eq!(tree.fee_balance(), 0);
    }

    let layout: &mut Layout = wincode::deserialize_mut(&mut bytes).expect("reload layout");
    assert_eq!(layout._reserved, [0u8; TREE_RESERVED_BYTES]);
    assert_eq!(layout.fees, fees);
    assert_eq!(layout.fee_balance, 0);
    assert_eq!(layout.tree_id, 0x0102);
    assert_eq!(bytes.get(2..4), Some(&[0x02, 0x01][..]));
}

#[test]
fn deserialize_mut_round_trip() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    {
        let layout: &mut Layout = wincode::deserialize_mut(&mut bytes).expect("cast");
        layout.utxo.init(UTXO_TREE_HEIGHT).unwrap();
        let mut leaf = [0u8; 32];
        leaf[31] = 9;
        layout.utxo.append(leaf, 9).unwrap();
        *layout.nullifier.root_history.roots.get_mut(3).unwrap() = [7u8; 32];
    }
    let reloaded: &mut Layout = wincode::deserialize_mut(&mut bytes).expect("reload");
    assert_eq!(reloaded.utxo.next_index(), 1);
    assert_eq!(
        reloaded.nullifier.root_history.roots.get(3),
        Some(&[7u8; 32])
    );
}
