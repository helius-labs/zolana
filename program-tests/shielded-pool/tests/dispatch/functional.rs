use solana_instruction::Instruction;
use zolana_interface::instruction::tag;

use crate::common::program_test;

#[test]
fn direct_emit_event_is_a_noop_and_is_not_indexed() {
    let mut rpc = program_test();
    let outcome = rpc
        .create_and_send_default_payer_transaction(
            &[Instruction {
                program_id: rpc.program_id,
                accounts: vec![],
                data: vec![tag::EMIT_EVENT],
            }],
            &[],
        )
        .expect("emit-event no-op");
    assert!(outcome.events.is_empty());
    assert!(rpc.indexer().utxos().is_empty());
}
