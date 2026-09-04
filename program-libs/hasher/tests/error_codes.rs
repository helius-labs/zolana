use solana_program_error::ProgramError;
use zolana_hasher::HasherError;

#[test]
fn error_codes_are_stable() {
    let cases = [
        (HasherError::IntegerOverflow, 8001),
        (HasherError::InvalidInputLength(32, 31), 8005),
        (HasherError::InvalidNumFields, 8006),
    ];
    for (error, code) in cases {
        assert_eq!(u32::from(error), code);
    }
}

#[test]
fn error_codes_stay_out_of_shielded_pool_space() {
    let codes = [
        u32::from(HasherError::IntegerOverflow),
        u32::from(HasherError::InvalidInputLength(32, 31)),
        u32::from(HasherError::InvalidNumFields),
    ];
    for code in codes {
        assert!((8000..9000).contains(&code));
    }
    assert_eq!(
        ProgramError::from(HasherError::IntegerOverflow),
        ProgramError::Custom(8001)
    );
}
