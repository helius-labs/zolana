use proptest::prelude::*;
use solana_instruction::Instruction;

use shielded_pool_tests::support::mollusk::{deposit_fixture, setup_mollusk};

// Failure persistence is left at the proptest default, so any failing case is
// recorded under `proptest-regressions/` (commit those files) and replays on
// every later run.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_account_free_instruction_bytes_are_deterministic(
        cases in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..256), 1..32)
    ) {
        let (mollusk, program_id) = setup_mollusk();
        for data in cases {
            let instruction = Instruction {
                program_id,
                accounts: Vec::new(),
                data,
            };
            let first = mollusk.process_instruction(&instruction, &[]);
            let second = mollusk.process_instruction(&instruction, &[]);
            prop_assert_eq!(first.raw_result, second.raw_result);
            prop_assert_eq!(first.resulting_accounts, second.resulting_accounts);
        }
    }

    #[test]
    fn valid_deposit_instruction_and_account_mutations_are_deterministic(
        mutations in prop::collection::vec((0u8..11, any::<usize>(), any::<u8>()), 1..24)
    ) {
        let (mollusk, valid, original_accounts) = deposit_fixture();
        for (kind, index, value) in mutations {
            let mut instruction = valid.clone();
            let mut accounts = original_accounts.clone();
            match kind {
                0 => {
                    let end = index % instruction.data.len();
                    instruction.data.truncate(end);
                }
                1 => {
                    let data_index = index % instruction.data.len();
                    *instruction
                        .data
                        .get_mut(data_index)
                        .expect("instruction byte") ^= value | 1;
                }
                2 => {
                    let account_index = index % instruction.accounts.len();
                    instruction.accounts.remove(account_index);
                    accounts.remove(account_index);
                }
                3 => {
                    instruction
                        .accounts
                        .get_mut(1)
                        .expect("depositor meta")
                        .is_signer = false;
                }
                4 => {
                    instruction
                        .accounts
                        .first_mut()
                        .expect("tree meta")
                        .is_writable = false;
                }
                5 => instruction.accounts.swap(0, 1),
                6 => {
                    let mut wrong_owner = [value; 32];
                    if solana_pubkey::Pubkey::new_from_array(wrong_owner)
                        == accounts.first().expect("tree account").1.owner
                    {
                        *wrong_owner.first_mut().expect("owner byte") ^= 1;
                    }
                    accounts.first_mut().expect("tree account").1.owner =
                        solana_pubkey::Pubkey::new_from_array(wrong_owner);
                }
                7 => {
                    let tree = accounts.first_mut().expect("tree account");
                    let end = index % tree.1.data.len();
                    tree.1.data.truncate(end);
                }
                8 => accounts
                    .last_mut()
                    .expect("program account")
                    .1
                    .executable = false,
                9 => {
                    accounts
                        .get_mut(1)
                        .expect("depositor account")
                        .1
                        .lamports = 0;
                }
                10 => {
                    let tree_data = &mut accounts.first_mut().expect("tree account").1.data;
                    let data_index = index % tree_data.len();
                    *tree_data.get_mut(data_index).expect("tree data byte") ^= value | 1;
                }
                _ => unreachable!(),
            }

            let first = mollusk.process_instruction(&instruction, &accounts);
            let second = mollusk.process_instruction(&instruction, &accounts);
            prop_assert_eq!(&first.raw_result, &second.raw_result);
            prop_assert_eq!(&first.program_result, &second.program_result);
            prop_assert_eq!(&first.return_data, &second.return_data);
            prop_assert_eq!(&first.resulting_accounts, &second.resulting_accounts);
            prop_assert_eq!(first.compute_units_consumed, second.compute_units_consumed);
        }
    }
}
