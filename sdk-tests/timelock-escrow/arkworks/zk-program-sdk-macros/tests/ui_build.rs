#[test]
fn width_errors_fail_the_build() {
    let cases = trybuild::TestCases::new();
    cases.pass("tests/ui/widths/pass/*.rs");
    cases.compile_fail("tests/ui/widths/fail/*.rs");
}
