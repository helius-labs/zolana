use bytemuck::Zeroable;
use spl_discriminator::SplDiscriminate;

use super::*;

fn account() -> VaultAccount {
    let mut account = VaultAccount::zeroed();
    account.discriminator = VaultAccount::SPL_DISCRIMINATOR;
    account.token_available = 123_456;
    account.shares_issued = 654_321;
    account.pending_fees_sf = (u128::from(u64::MAX) + 123).to_le_bytes();
    account
}

#[test]
fn reads_vault_fields_from_unaligned_account_data() -> Result<()> {
    let account = account();
    let mut bytes = vec![0];
    bytes.extend_from_slice(bytemuck::bytes_of(&account));
    let data = bytes.get(1..).ok_or_else(|| anyhow!("missing account"))?;
    assert_eq!(
        VaultState::from_data(data)?,
        VaultState {
            token_available: 123_456,
            shares_issued: 654_321,
            pending_fees_sf: u128::from(u64::MAX) + 123,
        }
    );
    Ok(())
}

#[test]
fn rejects_incorrect_account_lengths() -> Result<()> {
    let account = account();
    let bytes = bytemuck::bytes_of(&account);
    for len in [0, 8, VaultAccount::SIZE - 1] {
        let truncated = bytes
            .get(..len)
            .ok_or_else(|| anyhow!("invalid test length"))?;
        assert!(VaultState::from_data(truncated).is_err());
    }
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert!(VaultState::from_data(&extended).is_err());
    Ok(())
}

#[test]
fn rejects_incorrect_account_discriminator() {
    let mut account = account();
    account.discriminator = spl_discriminator::ArrayDiscriminator::UNINITIALIZED;
    assert!(VaultState::from_data(bytemuck::bytes_of(&account)).is_err());
}

#[test]
fn rejects_allocations_in_every_slot() -> Result<()> {
    let template = account();
    for slot in 0..template.vault_allocation_strategy.len() {
        let mut account = template;
        account
            .vault_allocation_strategy
            .get_mut(slot)
            .ok_or_else(|| anyhow!("missing allocation slot"))?
            .reserve = Address::new_from_array([1; 32]);
        assert_eq!(
            VaultState::from_data(bytemuck::bytes_of(&account))
                .unwrap_err()
                .to_string(),
            "allocated kVaults require reserve AUM pricing; this example supports unallocated vaults"
        );
    }
    Ok(())
}

#[test]
fn ignores_non_reserve_fields_in_empty_allocation_slots() -> Result<()> {
    let mut account = account();
    for allocation in &mut account.vault_allocation_strategy {
        allocation.ctoken_vault = Address::new_from_array([1; 32]);
        allocation.token_allocation_cap = u64::MAX;
    }
    assert_eq!(
        VaultState::from_data(bytemuck::bytes_of(&account))?,
        VaultState {
            token_available: 123_456,
            shares_issued: 654_321,
            pending_fees_sf: u128::from(u64::MAX) + 123,
        }
    );
    Ok(())
}
