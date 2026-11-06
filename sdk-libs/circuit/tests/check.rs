use spr_circuit::{CircuitError, CircuitErrorKind, Field, checked, require, require_eq};

fn location(error: &CircuitError) -> (&'static str, u32) {
    match error.kind() {
        CircuitErrorKind::RequirementFailed { file, line, .. } => (*file, *line),
        other => panic!("expected a failed requirement, got {other:?}"),
    }
}

#[test]
fn a_failed_requirement_becomes_an_error_at_its_call_site() {
    let mut line = 0;
    let error = checked(|| -> Result<(), CircuitError> {
        line = line!() + 1;
        require(false);
        Ok(())
    })
    .unwrap_err();
    assert_eq!(location(&error), (file!(), line));
}

#[test]
fn the_first_failure_wins_over_later_failures_and_the_closure_result() {
    let mut line = 0;
    let error = checked(|| -> Result<(), CircuitError> {
        line = line!() + 1;
        require_eq(Field::one(), Field::zero());
        require(false);
        Err(CircuitErrorKind::InvalidInput("later").into())
    })
    .unwrap_err();
    assert_eq!(location(&error), (file!(), line));
}

#[test]
fn passing_requirements_return_the_closure_result() {
    let value = checked(|| {
        require(true);
        require_eq(7u64, 7u64);
        Ok(5u8)
    });
    assert_eq!(value, Ok(5));
}

#[test]
fn a_nested_scope_does_not_hide_or_leak_failures() {
    let mut lines = (0, 0);
    let mut inner = None;
    let outer = checked(|| -> Result<(), CircuitError> {
        inner = Some(checked(|| -> Result<(), CircuitError> {
            lines.0 = line!() + 1;
            require(false);
            Ok(())
        }));
        lines.1 = line!() + 1;
        require(false);
        Ok(())
    });
    assert_eq!(location(&inner.unwrap().unwrap_err()), (file!(), lines.0));
    assert_eq!(location(&outer.unwrap_err()), (file!(), lines.1));

    let after_failed_inner = checked(|| {
        let _ = checked(|| -> Result<(), CircuitError> {
            require(false);
            Ok(())
        });
        Ok(())
    });
    assert_eq!(after_failed_inner, Ok(()));
}

#[test]
fn a_failure_outside_a_scope_still_panics_without_the_compared_values() {
    let panic = std::panic::catch_unwind(|| require_eq(Field::from(123_456u64), Field::zero()))
        .unwrap_err();
    let message = panic.downcast_ref::<String>().unwrap();
    assert!(message.starts_with("requirement failed at "), "{message}");
    assert!(!message.contains("123456"), "{message}");
}

#[test]
fn a_scope_is_restored_after_its_closure_unwinds() {
    let _ = std::panic::catch_unwind(|| {
        checked(|| -> Result<(), CircuitError> { panic!("unrelated") })
    });
    let outside = std::panic::catch_unwind(|| require(false));
    assert!(
        outside.is_err(),
        "the scope must not stay open after an unwind"
    );
}
