use spr_program::{
    ArrayVec, ClientError, ClientInputs, Field, InputRecords, TransactionOptions, TxContext, input,
};

#[input]
#[derive(ClientInputs)]
pub struct Numbers {
    pub context: TxContext,
    pub amounts: ArrayVec<u64, 3>,
    pub commitment: Field,
}

fn client(amounts: Vec<u64>, commitment: &str) -> NumbersClient {
    NumbersClient {
        context: TransactionOptions {
            blinding_seed: Some([0; 32]),
            output_tree_id: Some(7),
        },
        amounts,
        commitment: commitment.into(),
    }
}

#[test]
fn generated_conversion_keeps_context_padding_and_canonical_scalars() {
    let numbers = Numbers::from_client(client(vec![7, 2], "42"), &mut InputRecords::new()).unwrap();
    assert_eq!(
        (
            numbers.context.output_tree_id,
            numbers.context.uses_output_tree_id,
            numbers.amounts.padded(),
            numbers.commitment.to_decimal(),
        ),
        (7, true, [7, 2, 0], "42".into()),
    );
}

#[test]
fn generated_conversion_refuses_excess_capacity_and_noncanonical_scalars() {
    assert!(matches!(
        Numbers::from_client(client(vec![1; 4], "42"), &mut InputRecords::new()),
        Err(ClientError::TooManyInputs {
            capacity: 3,
            found: 4
        })
    ));
    assert!(matches!(
        Numbers::from_client(client(vec![1], "01"), &mut InputRecords::new()),
        Err(ClientError::InvalidInput(_))
    ));
}

#[input]
#[derive(ClientInputs)]
pub struct Destination {
    pub commitment: Field,
    pub amount: u64,
}

#[input]
#[derive(ClientInputs)]
pub struct Terms {
    pub destination: Destination,
    pub blinding: Field,
}

#[input]
#[derive(ClientInputs)]
pub struct Create {
    pub tx_context: TxContext,
    pub terms: Terms,
}

fn nested(commitment: &str) -> CreateClient {
    CreateClient {
        tx_context: TransactionOptions {
            blinding_seed: Some([0; 32]),
            output_tree_id: Some(7),
        },
        terms: TermsClient {
            destination: DestinationClient {
                commitment: commitment.into(),
                amount: 9,
            },
            blinding: "13".into(),
        },
    }
}

#[test]
fn nested_structs_convert_recursively_without_field_attributes() {
    let converted = Create::from_client(nested("42"), &mut InputRecords::new()).unwrap();
    assert_eq!(
        (
            converted.tx_context.output_tree_id,
            converted.terms.destination.amount,
            converted.terms.destination.commitment.to_decimal(),
            converted.terms.blinding.to_decimal()
        ),
        (7, 9, "42".into(), "13".into()),
    );
}

#[test]
fn nested_conversion_preserves_canonical_scalar_validation() {
    assert!(matches!(
        Create::from_client(nested("01"), &mut InputRecords::new()),
        Err(ClientError::InvalidInput(_))
    ));
}
