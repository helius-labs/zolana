use custom_ring_interface::{
    CoSigner, DepositAudit, RingAccount, RingProgramConfig, CO_SIGNER, DEPOSIT_AUDIT,
    MAX_CO_SIGNER_THRESHOLDS, RING_PROGRAM_CONFIG,
};
use solana_address::Address;

const PROGRAM: Address = Address::new_from_array([7; 32]);

fn config() -> RingProgramConfig {
    RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: Address::new_from_array([1; 32]),
        auditor_pubkey: [2; 33],
        bump: 255,
        has_policy: 1,
        key_escrow: 0,
    }
}

#[test]
fn decode_needs_the_owner_the_length_and_the_discriminator() {
    let bytes = bytemuck::bytes_of(&config()).to_vec();
    assert_eq!(RingProgramConfig::decode(&PROGRAM, &PROGRAM, &bytes), Some(config()));
    let other = Address::new_from_array([8; 32]);
    assert_eq!(RingProgramConfig::decode(&other, &PROGRAM, &bytes), None);
    assert_eq!(RingProgramConfig::decode(&PROGRAM, &PROGRAM, &bytes[1..]), None);
    let mut uninitialized = bytes.clone();
    uninitialized[0] = 0;
    assert_eq!(RingProgramConfig::decode(&PROGRAM, &PROGRAM, &uninitialized), None);
    assert_eq!(CoSigner::decode(&PROGRAM, &PROGRAM, &bytes), None);
}

#[test]
fn decode_refuses_values_no_setter_writes() {
    let mut cosigner: CoSigner = bytemuck::Zeroable::zeroed();
    cosigner.discriminator = CO_SIGNER;
    cosigner.threshold_count = MAX_CO_SIGNER_THRESHOLDS as u8;
    assert!(CoSigner::decode(&PROGRAM, &PROGRAM, bytemuck::bytes_of(&cosigner)).is_some());
    cosigner.threshold_count += 1;
    assert_eq!(CoSigner::decode(&PROGRAM, &PROGRAM, bytemuck::bytes_of(&cosigner)), None);
    assert!(cosigner.thresholds().is_empty());

    let audit = |required| DepositAudit {
        discriminator: DEPOSIT_AUDIT,
        required,
        bump: 255,
    };
    assert!(DepositAudit::decode(&PROGRAM, &PROGRAM, bytemuck::bytes_of(&audit(1))).is_some());
    assert_eq!(
        DepositAudit::decode(&PROGRAM, &PROGRAM, bytemuck::bytes_of(&audit(2))),
        None
    );
}
