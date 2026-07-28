//! A shielded participant in zone lifecycle tests.

use zolana_interface::instruction::ZoneAssetDeposit;
use zolana_test_utils::harness::DepositRecord as SharedDepositRecord;

/// The extra account snapshots an SPL zone-deposit assert needs.
pub(crate) use zolana_test_utils::harness::SplDepositAccounts as SplZoneDepositAccounts;

/// What a zone deposit records so the separate assertion can verify
/// it with `assert_zone_deposit` (which needs the sent data and the pre-deposit
/// account snapshots). `spl` is `Some` for token zone deposits.
pub(crate) type ZoneDepositRecord = SharedDepositRecord<ZoneAssetDeposit>;
