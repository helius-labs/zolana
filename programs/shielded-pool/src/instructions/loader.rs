use pinocchio::AccountView;

pub struct MutableTreeAccounts<'a> {
    pub tree: &'a mut AccountView,
}

/// Mutable view of a validated account's data buffer.
///
/// This is the single place that performs `borrow_unchecked_mut`; instruction
/// handlers call it instead of writing their own `unsafe` block, so the safety
/// rationale lives here rather than being copy-pasted across call sites.
///
/// SAFETY: `account` must be a writable account the caller already validated
/// and must not be aliased by any other live borrow while the returned slice is
/// in scope. Each pinocchio account owns a distinct data buffer and these
/// handlers never borrow the same account twice, so the unchecked borrow is
/// sound.
pub fn account_data_mut(account: &mut AccountView) -> &mut [u8] {
    // SAFETY: upheld by the caller per the function contract above.
    unsafe { account.borrow_unchecked_mut() }
}
