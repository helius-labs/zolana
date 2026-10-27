# ZK Program SDK -- Scenario Benchmark

Constraints and proving time for every proof the scenario tests generate. **Constraints** is the circuit's R1CS constraint count, taken from the same synthesis its proving key is generated from. **Proof time** is the elapsed time of `Groth16Prover::prove`, which runs the circuit natively, checks that the constraints are satisfied, creates the Groth16 proof and verifies it once.

Regenerate with `just bench-zolana-program`. It runs a release build one test at a time, so each proof has every core for its parallel proving.

| Test | Circuit | Proof | Constraints | Proof time |
| ---- | ------- | ----- | ----------: | ---------: |
| `s01_sol_payment::sol_payment_prove_and_verify` | `Payment` | payment | 8,131 | 153 ms |
| `s02_spl_payment::spl_payment_prove_and_verify` | `SplPayment` | spl payment | 6,903 | 58 ms |
| `s03_sweep::sweep_prove_and_verify` | `Sweep` | sweep | 6,778 | 56 ms |
| `s04_payment_across_shapes::payment_3x2_one_recipient_prove_and_verify` | `Payment<3, 1>` | payment | 9,921 | 72 ms |
| `s04_payment_across_shapes::payment_4x2_one_recipient_prove_and_verify` | `Payment<4, 1>` | payment | 11,722 | 68 ms |
| `s04_payment_across_shapes::payment_5x2_one_recipient_prove_and_verify` | `Payment<5, 1>` | payment | 13,534 | 69 ms |
| `s04_payment_across_shapes::payment_5x4_prove_and_verify` | `Payment<5, 3>` | payment | 17,835 | 97 ms |
| `s05_fan_out::fan_out_prove_and_verify` | `FanOut` | fan-out | 19,150 | 91 ms |
| `s06_merge::merge_prove_and_verify` | `Merge` | merge | 73,810 | 202 ms |
| `s07_top_up::top_up_prove_and_verify` | `TopUp` | top-up | 5,594 | 41 ms |
| `s08_deposit_to_another_owner::deposit_to_another_owner_prove_and_verify` | `Deposit` | deposit | 7,603 | 43 ms |
| `s09_partial_withdrawal::partial_withdrawal_prove_and_verify` | `Withdrawal` | withdrawal | 5,659 | 40 ms |
| `s10_full_withdrawal::full_withdrawal_prove_and_verify` | `Withdrawal` | withdrawal | 4,613 | 39 ms |
| `s11_two_asset_payment::two_asset_payment_prove_and_verify` | `TwoAssetPayment` | two-asset payment | 14,951 | 62 ms |
| `s12_two_party_swap::two_party_swap_prove_and_verify` | `Swap` | swap | 10,828 | 50 ms |
| `s13_counter_create::counter_create_prove_and_verify` | `CounterCreate` | counter create | 6,133 | 40 ms |
| `s14_counter_increment::counter_increment_prove_and_verify` | `Increment` | increment | 5,309 | 37 ms |
| `s15_counter_decrement::counter_decrement_prove_and_verify` | `Decrement` | decrement | 5,309 | 37 ms |
| `s16_counter_reset::counter_reset_prove_and_verify` | `Reset` | reset | 5,496 | 43 ms |
| `s17_counter_close::counter_close_prove_and_verify` | `Close` | close | 4,523 | 34 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `CounterCreate` | create | 6,133 | 38 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `Increment` | increment | 5,309 | 35 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `Increment` | second increment | 5,309 | 38 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `Decrement` | decrement | 5,309 | 37 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `Reset` | reset | 5,496 | 40 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `Close` | close | 4,523 | 35 ms |
| `s19_typed_state_create::typed_state_create_prove_and_verify` | `TypedCreate` | typed create | 7,398 | 45 ms |
| `s20_typed_state_update::typed_state_update_prove_and_verify` | `TypedUpdate` | typed update | 7,256 | 44 ms |
| `s21_nested_array_state::nested_array_state_prove_and_verify` | `PortfolioCreate` | portfolio create | 8,092 | 39 ms |
| `s22_create_and_update::create_and_update_prove_and_verify` | `CreateAndUpdate` | create and update | 7,650 | 49 ms |
| `s23_update_two::update_two_prove_and_verify` | `UpdateTwo` | update two | 10,625 | 55 ms |
| `s24_create_two::create_two_prove_and_verify` | `CreateTwo` | create two | 10,067 | 57 ms |
| `s25_read_with_threshold::read_with_threshold_prove_and_verify` | `ReadThreshold` | read | 5,309 | 40 ms |
| `s26_compare_two::compare_two_prove_and_verify` | `CompareTwo` | compare | 9,838 | 52 ms |
| `s27_escrow::escrow_prove_and_verify` | `Escrow` | escrow | 8,660 | 50 ms |
| `s28_escrow_withdraw::escrow_withdraw_prove_and_verify` | `Withdraw` | withdraw | 5,620 | 39 ms |
| `s29_spl_escrow_and_withdraw::spl_escrow_then_withdraw_prove_and_verify` | `Escrow` | escrow | 8,660 | 52 ms |
| `s29_spl_escrow_and_withdraw::spl_escrow_then_withdraw_prove_and_verify` | `Withdraw` | withdraw | 5,620 | 40 ms |
| `s30_split_withdrawal::split_withdrawal_prove_and_verify` | `SplitWithdraw` | split withdraw | 7,802 | 41 ms |
| `s31_order_make::order_make_prove_and_verify` | `Make` | make | 9,330 | 52 ms |
| `s32_order_take::order_take_prove_and_verify` | `Take` | take | 11,214 | 63 ms |
| `s33_order_cancel::order_cancel_prove_and_verify` | `Cancel` | cancel | 5,742 | 36 ms |
| `s34_settle_or_refund::settle_or_refund_prove_and_verify` | `Settle` | settle | 11,856 | 54 ms |
| `s34_settle_or_refund::settle_or_refund_prove_and_verify` | `Settle` | refund | 11,856 | 59 ms |
| `s35_create_issuer::create_issuer_prove_and_verify` | `CreateIssuer` | create issuer | 6,628 | 40 ms |
| `s36_issue_credential::issue_credential_prove_and_verify` | `IssueCredential` | issue credential | 8,820 | 52 ms |
| `s37_verify_credential::verify_credential_prove_and_verify` | `VerifyCredential` | verify credential | 7,076 | 41 ms |
| `s38_allowlisted_payment::allowlisted_payment_prove_and_verify` | `AllowlistedPayment` | allowlisted payment | 9,125 | 51 ms |
| `s39_airdrop_pool::airdrop_pool_prove_and_verify` | `CreatePool` | pool | 6,901 | 42 ms |
| `s40_airdrop_claim::airdrop_claim_prove_and_verify` | `Claim` | claim | 9,965 | 54 ms |
| `s41_vesting_claim::vesting_claim_prove_and_verify` | `VestingClaim` | vesting claim | 9,058 | 51 ms |
| `s42_create_poll::create_poll_prove_and_verify` | `CreatePoll` | create poll | 6,717 | 43 ms |
| `s43_cast_vote::cast_vote_prove_and_verify` | `CastVote` | vote | 8,644 | 49 ms |
| `s44_mixer_deposit::mixer_deposit_prove_and_verify` | `MixerDeposit` | mixer deposit | 7,028 | 42 ms |
| `s45_mixer_withdrawal::mixer_withdrawal_prove_and_verify` | `MixerWithdrawal` | mixer withdrawal | 5,915 | 40 ms |
| `s46_another_output_tree::another_output_tree_prove_and_verify` | `Payment` | payment | 8,131 | 44 ms |
| `s47_inputs_from_two_trees::inputs_from_two_trees_prove_and_verify` | `Payment<3, 3>` | payment | 14,222 | 57 ms |
| `s48_program_chosen_blinding_seed::program_chosen_blinding_seed_prove_and_verify` | `Take` | take | 11,214 | 59 ms |
| `s49_no_public_fields::no_public_fields_prove_and_verify` | `PrivateSweep` | sweep | 6,751 | 41 ms |
| `s50_unique_counter_create::unique_counter_create_prove_and_verify` | `UniqueCounterCreate` | unique counter create | 4,094 | 35 ms |
