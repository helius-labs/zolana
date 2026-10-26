use super::*;

#[test]
fn exact_members_are_accepted_in_any_order() {
    let expected = [Pubkey::new_unique(), Pubkey::new_unique()];
    let actual = [expected[1], expected[0]];
    verify_role_members("ring", &Pubkey::new_unique(), &actual, &expected, &[])
        .expect("exact members must be accepted regardless of order");
}

#[test]
fn additional_members_are_rejected_by_default() {
    let expected = [Pubkey::new_unique()];
    let extra = Pubkey::new_unique();
    let actual = [expected[0], extra];
    let settings = Pubkey::new_unique();
    let error = verify_role_members("ring", &settings, &actual, &expected, &[]).unwrap_err();
    assert_eq!(error.to_string(), format!("ring smart account settings {settings} has unexpected member {extra}; pass --allow-extra-member {extra} to preserve this existing member"));
}

#[test]
fn only_explicitly_allowed_additional_members_are_accepted() {
    let expected = [Pubkey::new_unique()];
    let extra = Pubkey::new_unique();
    let actual = [expected[0], extra];
    verify_role_members("ring", &Pubkey::new_unique(), &actual, &expected, &[extra])
        .expect("the explicitly named extra member must be accepted");
}

#[test]
fn another_additional_member_still_fails() {
    let expected = [Pubkey::new_unique()];
    let extra = Pubkey::new_unique();
    let unexpected = Pubkey::new_unique();
    let actual = [expected[0], extra, unexpected];
    let settings = Pubkey::new_unique();
    let error = verify_role_members("ring", &settings, &actual, &expected, &[extra]).unwrap_err();
    assert_eq!(error.to_string(), format!("ring smart account settings {settings} has unexpected member {unexpected}; pass --allow-extra-member {unexpected} to preserve this existing member"));
}

#[test]
fn allowing_an_additional_member_does_not_replace_a_required_member() {
    let expected = [Pubkey::new_unique(), Pubkey::new_unique()];
    let extra = Pubkey::new_unique();
    let actual = [expected[0], extra];
    let settings = Pubkey::new_unique();
    let error = verify_role_members("ring", &settings, &actual, &expected, &[extra]).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "ring smart account settings {settings} does not list expected member {}",
            expected[1]
        ),
    );
}

#[test]
fn duplicate_members_are_rejected_even_when_explicitly_allowed() {
    let expected = [Pubkey::new_unique()];
    let extra = Pubkey::new_unique();
    let actual = [expected[0], extra, extra];
    let settings = Pubkey::new_unique();
    let error = verify_role_members("ring", &settings, &actual, &expected, &[extra]).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("ring smart account settings {settings} has duplicate member {extra}"),
    );
}
