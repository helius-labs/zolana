use zolana_keypair::ShieldedAddress;
use zolana_program::{Owner, PublicField, PublicFieldKind, PublicInputLayout};
use zolana_transaction::Mint;

use super::{Settlement, Unconditional};

fn array(len: usize, item: PublicFieldKind) -> PublicFieldKind {
    PublicFieldKind::Array {
        len,
        item: Box::new(item),
    }
}

#[test]
fn the_layout_lists_every_field_in_order_with_its_kind() {
    assert_eq!(
        Settlement::layout(),
        vec![
            ("amount", PublicFieldKind::Integer { bits: 64 }),
            ("paid", PublicFieldKind::Bool),
            ("recipient", PublicFieldKind::Hash),
            ("signers", array(2, PublicFieldKind::Hash)),
            (
                "limits",
                array(2, array(2, PublicFieldKind::Integer { bits: 32 }))
            ),
        ]
    );
}

#[test]
fn a_unit_struct_has_an_empty_layout() {
    assert_eq!(Unconditional::layout(), Vec::new());
}

#[test]
fn each_public_field_type_reports_its_kind() {
    assert_eq!(
        [
            u16::kind(),
            u32::kind(),
            u64::kind(),
            u128::kind(),
            bool::kind(),
            <[u8; 32]>::kind(),
            ShieldedAddress::kind(),
            Owner::kind(),
            Mint::kind(),
            <[[bool; 3]; 1]>::kind(),
        ],
        [
            PublicFieldKind::Integer { bits: 16 },
            PublicFieldKind::Integer { bits: 32 },
            PublicFieldKind::Integer { bits: 64 },
            PublicFieldKind::Integer { bits: 128 },
            PublicFieldKind::Bool,
            PublicFieldKind::Hash,
            PublicFieldKind::Hash,
            PublicFieldKind::Hash,
            PublicFieldKind::Hash,
            array(1, array(3, PublicFieldKind::Bool)),
        ]
    );
}
