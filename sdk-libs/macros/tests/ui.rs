mod support;

#[test]
fn compile_errors() -> Result<(), Box<dyn std::error::Error>> {
    support::with_normalized_git_paths(|| {
        trybuild::TestCases::new().compile_fail("tests/ui/fail/*.rs");
    })
}
