use swap_program::instructions::shared::{check_after_window, check_within_window};

#[test]
fn take_window_boundary() {
    assert!(check_within_window(0, 100).is_ok());
    assert!(check_within_window(100, 100).is_ok());
    assert!(check_within_window(99, 100).is_ok());
    assert!(check_within_window(101, 100).is_err());
    assert!(check_within_window(-1, 100).is_err());
}

#[test]
fn cancel_window_boundary() {
    assert!(check_after_window(100, 100).is_err());
    assert!(check_after_window(99, 100).is_err());
    assert!(check_after_window(101, 100).is_ok());
    assert!(check_after_window(-1, 100).is_err());
}

#[test]
fn windows_are_mutually_exclusive() {
    let expiry = 100u64;
    for now in [0i64, 50, 100, 101, 1_000] {
        assert_ne!(
            check_within_window(now, expiry).is_ok(),
            check_after_window(now, expiry).is_ok()
        );
    }
}
