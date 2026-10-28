# ZK Program SDK -- Scenario Benchmark

Constraints and proving time for every proof the scenario tests generate. **Constraints** is the circuit's R1CS constraint count, taken from the same synthesis its proving key is generated from. **Proof time** is the elapsed time of `Groth16Prover::prove`, which runs the circuit natively, checks that the constraints are satisfied, creates the Groth16 proof and verifies it once.

Regenerate with `just bench-spr-program`. It runs a release build one test at a time, so each proof has every core for its parallel proving.

| Test | Circuit | Proof | Constraints | Proof time |
| ---- | ------- | ----- | ----------: | ---------: |
| `s01_sol_payment::sol_payment_prove_and_verify` | `Payment` | payment | 8,042 | 42 ms |
| `s02_spl_payment::spl_payment_prove_and_verify` | `SplPayment` | spl payment | 6,893 | 40 ms |
| `s03_sweep::sweep_prove_and_verify` | `Sweep` | sweep | 6,689 | 40 ms |
| `s04_payment_across_shapes::payment_3x2_one_recipient_prove_and_verify` | `Payment<3, 1>` | payment | 9,742 | 54 ms |
| `s04_payment_across_shapes::payment_4x2_one_recipient_prove_and_verify` | `Payment<4, 1>` | payment | 11,442 | 56 ms |
| `s04_payment_across_shapes::payment_5x2_one_recipient_prove_and_verify` | `Payment<5, 1>` | payment | 13,142 | 61 ms |
| `s04_payment_across_shapes::payment_5x4_prove_and_verify` | `Payment<5, 3>` | payment | 17,443 | 81 ms |
| `s05_fan_out::fan_out_prove_and_verify` | `FanOut` | fan-out | 19,140 | 89 ms |
| `s06_merge::merge_prove_and_verify` | `Merge` | merge | 64,490 | 161 ms |
| `s07_top_up::top_up_prove_and_verify` | `TopUp` | top-up | 5,584 | 39 ms |
| `s08_deposit_to_another_owner::deposit_to_another_owner_prove_and_verify` | `Deposit` | deposit | 7,593 | 43 ms |
| `s09_partial_withdrawal::partial_withdrawal_prove_and_verify` | `Withdrawal` | withdrawal | 5,649 | 45 ms |
| `s10_full_withdrawal::full_withdrawal_prove_and_verify` | `Withdrawal` | withdrawal | 4,603 | 41 ms |
| `s11_two_asset_payment::two_asset_payment_prove_and_verify` | `TwoAssetPayment` | two-asset payment | 14,729 | 67 ms |
| `s12_two_party_swap::two_party_swap_prove_and_verify` | `Swap` | swap | 10,797 | 61 ms |
| `s13_counter_create::counter_create_prove_and_verify` | `CounterCreate` | counter create | 6,123 | 42 ms |
| `s14_counter_increment::counter_increment_prove_and_verify` | `Increment` | increment | 5,309 | 44 ms |
| `s15_counter_decrement::counter_decrement_prove_and_verify` | `Decrement` | decrement | 5,309 | 40 ms |
| `s16_counter_reset::counter_reset_prove_and_verify` | `Reset` | reset | 5,496 | 44 ms |
| `s17_counter_close::counter_close_prove_and_verify` | `Close` | close | 4,523 | 43 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `CounterCreate` | create | 6,123 | 46 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `Increment` | increment | 5,309 | 43 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `Increment` | second increment | 5,309 | 39 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `Decrement` | decrement | 5,309 | 44 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `Reset` | reset | 5,496 | 45 ms |
| `s18_counter_lifecycle::counter_lifecycle_prove_and_verify` | `Close` | close | 4,523 | 42 ms |
| `s19_typed_state_create::typed_state_create_prove_and_verify` | `TypedCreate` | typed create | 7,388 | 48 ms |
| `s20_typed_state_update::typed_state_update_prove_and_verify` | `TypedUpdate` | typed update | 7,256 | 45 ms |
| `s21_nested_array_state::nested_array_state_prove_and_verify` | `PortfolioCreate` | portfolio create | 8,082 | 45 ms |
| `s22_create_and_update::create_and_update_prove_and_verify` | `CreateAndUpdate` | create and update | 7,650 | 47 ms |
| `s23_update_two::update_two_prove_and_verify` | `UpdateTwo` | update two | 10,625 | 47 ms |
| `s24_create_two::create_two_prove_and_verify` | `CreateTwo` | create two | 9,978 | 53 ms |
| `s25_read_with_threshold::read_with_threshold_prove_and_verify` | `ReadThreshold` | read | 5,309 | 34 ms |
| `s26_compare_two::compare_two_prove_and_verify` | `CompareTwo` | compare | 9,838 | 53 ms |
| `s27_escrow::escrow_prove_and_verify` | `Escrow` | escrow | 8,571 | 47 ms |
| `s28_escrow_withdraw::escrow_withdraw_prove_and_verify` | `Withdraw` | withdraw | 5,620 | 37 ms |
| `s29_spl_escrow_and_withdraw::spl_escrow_then_withdraw_prove_and_verify` | `Escrow` | escrow | 8,571 | 50 ms |
| `s29_spl_escrow_and_withdraw::spl_escrow_then_withdraw_prove_and_verify` | `Withdraw` | withdraw | 5,620 | 39 ms |
| `s30_split_withdrawal::split_withdrawal_prove_and_verify` | `SplitWithdraw` | split withdraw | 7,802 | 39 ms |
| `s31_order_make::order_make_prove_and_verify` | `Make` | make | 9,241 | 54 ms |
| `s32_order_take::order_take_prove_and_verify` | `Take` | take | 11,194 | 50 ms |
| `s33_order_cancel::order_cancel_prove_and_verify` | `Cancel` | cancel | 5,742 | 38 ms |
| `s34_settle_or_refund::settle_or_refund_prove_and_verify` | `Settle` | settle | 11,856 | 53 ms |
| `s34_settle_or_refund::settle_or_refund_prove_and_verify` | `Settle` | refund | 11,856 | 58 ms |
| `s35_create_issuer::create_issuer_prove_and_verify` | `CreateIssuer` | create issuer | 6,618 | 41 ms |
| `s36_issue_credential::issue_credential_prove_and_verify` | `IssueCredential` | issue credential | 8,820 | 48 ms |
| `s37_verify_credential::verify_credential_prove_and_verify` | `VerifyCredential` | verify credential | 7,076 | 50 ms |
| `s38_allowlisted_payment::allowlisted_payment_prove_and_verify` | `AllowlistedPayment` | allowlisted payment | 9,036 | 57 ms |
| `s39_airdrop_pool::airdrop_pool_prove_and_verify` | `CreatePool` | pool | 6,891 | 42 ms |
| `s40_airdrop_claim::airdrop_claim_prove_and_verify` | `Claim` | claim | 9,965 | 63 ms |
| `s41_vesting_claim::vesting_claim_prove_and_verify` | `VestingClaim` | vesting claim | 9,058 | 103 ms |
| `s42_create_poll::create_poll_prove_and_verify` | `CreatePoll` | create poll | 6,707 | 61 ms |
| `s43_cast_vote::cast_vote_prove_and_verify` | `CastVote` | vote | 8,644 | 57 ms |
| `s44_mixer_deposit::mixer_deposit_prove_and_verify` | `MixerDeposit` | mixer deposit | 7,018 | 45 ms |
| `s45_mixer_withdrawal::mixer_withdrawal_prove_and_verify` | `MixerWithdrawal` | mixer withdrawal | 5,915 | 43 ms |
| `s46_another_output_tree::another_output_tree_prove_and_verify` | `Payment` | payment | 8,042 | 46 ms |
| `s47_inputs_from_two_trees::inputs_from_two_trees_prove_and_verify` | `Payment<3, 3>` | payment | 14,043 | 62 ms |
| `s48_program_chosen_blinding_seed::program_chosen_blinding_seed_prove_and_verify` | `Take` | take | 11,194 | 61 ms |
| `s49_no_public_fields::no_public_fields_prove_and_verify` | `PrivateSweep` | sweep | 6,662 | 45 ms |
| `s50_unique_counter_create::unique_counter_create_prove_and_verify` | `UniqueCounterCreate` | unique counter create | 4,094 | 36 ms |
