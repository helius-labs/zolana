//! A shielded participant in a lifecycle scenario.

use zolana_interface::instruction::AssetDeposit;
use zolana_test_utils::harness::DepositRecord as SharedDepositRecord;

/// The extra account snapshots an SPL deposit assert needs.
pub(crate) use zolana_test_utils::harness::SplDepositAccounts;

/// What a deposit's action recorded, so the separate assert step can verify it
/// with `assert_deposit`/`assert_spl_deposit` (which need the sent data and the
/// pre-deposit account snapshots). `spl` is `Some` for token deposits.
pub(crate) type DepositRecord = SharedDepositRecord<AssetDeposit>;

/// One shielded participant: its key material, the wallet it syncs into, the
/// UTXOs it can currently spend, and the full set of UTXOs its wallet is expected
/// to hold after a sync (with `spent` flags), tracked for full-struct assertions.
pub(crate) type Actor = zolana_test_utils::harness::Actor<AssetDeposit>;
