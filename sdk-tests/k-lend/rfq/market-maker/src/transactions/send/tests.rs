use solana_transaction_status_client_types::TransactionConfirmationStatus;

use super::*;

fn status(error: Option<TransactionError>) -> Option<TransactionStatus> {
    Some(TransactionStatus {
        slot: 1,
        confirmations: Some(1),
        status: error.clone().map_or(Ok(()), Err),
        err: error,
        confirmation_status: Some(TransactionConfirmationStatus::Confirmed),
    })
}

#[test]
fn pending_attempts_prevent_early_failure_and_confirmation_wins() {
    let sends = [
        Sent {
            signature: Signature::from([1; 64]),
            last_valid_block_height: 100,
        },
        Sent {
            signature: Signature::from([2; 64]),
            last_valid_block_height: 200,
        },
    ];
    let failure = status(Some(TransactionError::InstructionError(
        0,
        InstructionError::Custom(42),
    )));
    assert_eq!(
        classify(&sends, &[failure.clone(), None], 150),
        StepStatus::Pending
    );
    assert_eq!(
        classify(&sends, std::slice::from_ref(&failure), 150),
        StepStatus::Pending
    );
    assert!(matches!(
        classify(&sends, &[failure.clone(), None], 201),
        StepStatus::Failed { code: Some(42), .. }
    ));
    assert_eq!(
        classify(&sends, &[failure, status(None)], 150),
        StepStatus::Confirmed {
            signature: Signature::from([2; 64])
        }
    );
    assert_eq!(classify(&sends, &[None, None], 201), StepStatus::Expired);
}
