use compression_example_program::error::CompressionError::*;

#[test]
fn error_codes_are_stable() {
    let table = [
        (InvalidInstructionData as u32, 12000),
        (InvalidAccounts as u32, 12001),
        (InvalidAuthority as u32, 12002),
        (InvalidPda as u32, 12003),
        (InvalidTree as u32, 12004),
        (InvalidTransact as u32, 12005),
        (InvalidAddress as u32, 12006),
        (InvalidState as u32, 12007),
        (HashingFailed as u32, 12008),
        (SerializationFailed as u32, 12009),
    ];
    for (got, want) in table {
        assert_eq!(got, want, "error code drifted");
    }
}
