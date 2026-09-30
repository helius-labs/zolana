use ark_bn254::Fr;
use zolana_program::{
    circuit::{Assert, Bool, CircuitType, CircuitVar, Constraints, Field, Select, Uint},
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError,
};

use crate::harness::fixture::{outcome, rule_broken, Fixture, Named, Refusal, Visit, Visited};

pub const FILE: &str = file!();

/// The rule of the SDK's booleanity check in `Bits::check_is_bool`.
pub const NOT_BOOLEAN: &str = "a value is neither 0 nor 1";

pub const NOT_ZERO_OR_ONE: Refusal = ("CircuitError.NotZeroOrOne", None, FILE);

pub const CONVERT_RULE: &str = "the output is the converted value";
pub const CONSTANT_RULE: &str = "the output is the constant";
pub const NOT_RULE: &str = "the output is not a";
pub const SELECT_RULE: &str = "the output is the selected branch";

pub fn broken(rule: &'static str) -> Refusal {
    rule_broken(rule, FILE)
}

fn bit(var: &CircuitVar) -> Result<Bool, CircuitError> {
    Bool::try_from(var)
}

type Convert = fn(&CircuitVar) -> Result<CircuitVar, CircuitError>;

pub const CONVERT_FORMS: [(&str, Convert); 5] = [
    ("Bool::try_from(x)", |x| {
        Ok(CircuitVar::from(Bool::try_from(x.clone())?))
    }),
    ("Bool::try_from(&x)", |x| {
        Ok(CircuitVar::from(Bool::try_from(x)?))
    }),
    ("Uint::<1>::from", |x| {
        Ok(CircuitVar::from(Uint::<1>::from(Bool::try_from(x)?)))
    }),
    ("Uint::<64>::from", |x| {
        Ok(CircuitVar::from(Uint::<64>::from(Bool::try_from(x)?)))
    }),
    ("Uint::<253>::from", |x| {
        Ok(CircuitVar::from(Uint::<253>::from(Bool::try_from(x)?)))
    }),
];

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Converted<const FORM: usize> {
    pub x: Field,
    pub out: Field,
}

impl<const FORM: usize> ConvertedCircuit<FORM> {
    fn output(&self) -> Result<CircuitVar, CircuitError> {
        let (_, form) = CONVERT_FORMS[FORM];
        form(&self.x)
    }
}

impl<const FORM: usize> Fixture<Result<CircuitVar, Refusal>> for Converted<FORM> {
    fn computed(circuit: &ConvertedCircuit<FORM>) -> Result<CircuitVar, Refusal> {
        outcome(circuit.output())
    }
}

impl<const FORM: usize> Constraints for ConvertedCircuit<FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.output()?.assert_equal(&self.out, CONVERT_RULE)
    }
}

pub fn convert_forms<V: Visit<Result<CircuitVar, Refusal>>>(
    visitor: &V,
    (x, out): (Field, Field),
) -> Visited<V::Output> {
    convert_form_names()
        .into_iter()
        .zip([
            visitor.visit(&Converted::<0> { x, out }),
            visitor.visit(&Converted::<1> { x, out }),
            visitor.visit(&Converted::<2> { x, out }),
            visitor.visit(&Converted::<3> { x, out }),
            visitor.visit(&Converted::<4> { x, out }),
        ])
        .collect()
}

pub fn convert_form_names() -> Vec<&'static str> {
    CONVERT_FORMS.iter().map(|(name, _)| *name).collect()
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ConstantClaim<const K: bool> {
    pub out: Field,
}

impl<const K: bool> Constraints for ConstantClaimCircuit<K> {
    fn constraints(&self) -> Result<(), CircuitError> {
        CircuitVar::from(Bool::constant(K)).assert_equal(&self.out, CONSTANT_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Not {
    pub a: Field,
    pub out: Field,
}

impl NotCircuit {
    fn output(&self) -> Result<CircuitVar, CircuitError> {
        Ok(CircuitVar::from(bit(&self.a)?.not()))
    }
}

impl Fixture<Result<CircuitVar, Refusal>> for Not {
    fn computed(circuit: &NotCircuit) -> Result<CircuitVar, Refusal> {
        outcome(circuit.output())
    }
}

impl Constraints for NotCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.output()?.assert_equal(&self.out, NOT_RULE)
    }
}

pub struct Gate {
    pub name: &'static str,
    pub rule: &'static str,
    /// The output for (a, b) = (0, 0), (0, 1), (1, 0) and (1, 1).
    pub truth: [bool; 4],
    pub apply: fn(&Bool, &Bool) -> Result<Bool, CircuitError>,
}

impl Gate {
    pub fn output(&self, a: bool, b: bool) -> bool {
        self.truth[2 * usize::from(a) + usize::from(b)]
    }

    /// The coefficients of 1, a, b and ab in the multilinear polynomial that
    /// agrees with the truth table on {0, 1}^2, circomlib's arithmetization
    /// of its gates.
    pub fn coefficients(&self) -> [Fr; 4] {
        let [c00, c01, c10, c11] = self.truth.map(Fr::from);
        [c00, c10 - c00, c01 - c00, c11 - c10 - c01 + c00]
    }

    pub fn polynomial(&self, a: Fr, b: Fr) -> Fr {
        let [one, a_term, b_term, product] = self.coefficients();
        one + a_term * a + b_term * b + product * a * b
    }
}

pub const GATES: [Gate; 6] = [
    Gate {
        name: "and",
        rule: "the output is a and b",
        truth: [false, false, false, true],
        apply: |a, b| Ok(a.and(b)),
    },
    Gate {
        name: "or",
        rule: "the output is a or b",
        truth: [false, true, true, true],
        apply: |a, b| Ok(a.or(b)),
    },
    Gate {
        name: "xor",
        rule: "the output is a xor b",
        truth: [false, true, true, false],
        apply: |a, b| Ok(a.xor(b)),
    },
    Gate {
        name: "nand",
        rule: "the output is a nand b",
        truth: [true, true, true, false],
        apply: |a, b| Ok(a.nand(b)),
    },
    Gate {
        name: "implies",
        rule: "the output is a implies b",
        truth: [true, true, false, true],
        apply: |a, b| Ok(a.implies(b)),
    },
    Gate {
        name: "is_equal",
        rule: "the output is whether a equals b",
        truth: [true, false, false, true],
        apply: |a, b| a.is_equal(b),
    },
];

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Variables<const GATE: usize> {
    pub a: Field,
    pub b: Field,
    pub out: Field,
}

impl<const GATE: usize> VariablesCircuit<GATE> {
    fn output(&self) -> Result<CircuitVar, CircuitError> {
        let (a, b) = (bit(&self.a)?, Bool::try_from(self.b.clone())?);
        Ok(CircuitVar::from((GATES[GATE].apply)(&a, &b)?))
    }
}

impl<const GATE: usize> Fixture<Result<CircuitVar, Refusal>> for Variables<GATE> {
    fn computed(circuit: &VariablesCircuit<GATE>) -> Result<CircuitVar, Refusal> {
        outcome(circuit.output())
    }
}

impl<const GATE: usize> Constraints for VariablesCircuit<GATE> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.output()?.assert_equal(&self.out, GATES[GATE].rule)
    }
}

pub struct ConstantForm {
    pub name: &'static str,
    pub constant: bool,
    pub constant_first: bool,
}

pub const CONSTANT_FORMS: [ConstantForm; 4] = [
    ConstantForm {
        name: "a, false",
        constant: false,
        constant_first: false,
    },
    ConstantForm {
        name: "a, true",
        constant: true,
        constant_first: false,
    },
    ConstantForm {
        name: "false, a",
        constant: false,
        constant_first: true,
    },
    ConstantForm {
        name: "true, a",
        constant: true,
        constant_first: true,
    },
];

impl ConstantForm {
    /// The gate's output as a function of the variable operand.
    pub fn output(&self, gate: &Gate, a: bool) -> bool {
        if self.constant_first {
            gate.output(self.constant, a)
        } else {
            gate.output(a, self.constant)
        }
    }
}

pub fn constant_form_names() -> Vec<&'static str> {
    CONSTANT_FORMS.iter().map(|form| form.name).collect()
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct WithConstant<const GATE: usize, const FORM: usize> {
    pub a: Field,
    pub out: Field,
}

impl<const GATE: usize, const FORM: usize> WithConstantCircuit<GATE, FORM> {
    fn output(&self) -> Result<CircuitVar, CircuitError> {
        let form = &CONSTANT_FORMS[FORM];
        let (a, k) = (bit(&self.a)?, Bool::constant(form.constant));
        let (left, right) = if form.constant_first {
            (&k, &a)
        } else {
            (&a, &k)
        };
        Ok(CircuitVar::from((GATES[GATE].apply)(left, right)?))
    }
}

impl<const GATE: usize, const FORM: usize> Fixture<Result<CircuitVar, Refusal>>
    for WithConstant<GATE, FORM>
{
    fn computed(circuit: &WithConstantCircuit<GATE, FORM>) -> Result<CircuitVar, Refusal> {
        outcome(circuit.output())
    }
}

impl<const GATE: usize, const FORM: usize> Constraints for WithConstantCircuit<GATE, FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.output()?.assert_equal(&self.out, GATES[GATE].rule)
    }
}

/// Visits `Variables<GATE>` of every gate for every pair, claiming
/// `claimed(gate, pair)`.
pub fn every_gate<V, P>(
    visitor: &V,
    pairs: &[P],
    claimed: impl Fn(&Gate, &P) -> (Field, Field, Field),
) -> Visited<Visited<V::Output>>
where
    V: Visit<Result<CircuitVar, Refusal>>,
    P: Named,
{
    fn one<const GATE: usize, V, P>(
        visitor: &V,
        pairs: &[P],
        claimed: &impl Fn(&Gate, &P) -> (Field, Field, Field),
    ) -> (&'static str, Visited<V::Output>)
    where
        V: Visit<Result<CircuitVar, Refusal>>,
        P: Named,
    {
        let gate = &GATES[GATE];
        let visited = pairs
            .iter()
            .map(|pair| {
                let (a, b, out) = claimed(gate, pair);
                (pair.name(), visitor.visit(&Variables::<GATE> { a, b, out }))
            })
            .collect();
        (gate.name, visited)
    }
    vec![
        one::<0, _, _>(visitor, pairs, &claimed),
        one::<1, _, _>(visitor, pairs, &claimed),
        one::<2, _, _>(visitor, pairs, &claimed),
        one::<3, _, _>(visitor, pairs, &claimed),
        one::<4, _, _>(visitor, pairs, &claimed),
        one::<5, _, _>(visitor, pairs, &claimed),
    ]
}

/// Visits `WithConstant<GATE, FORM>` of every gate and form with the operand
/// `a` and the claim `claimed(gate, form)`.
pub fn every_constant_form<V>(
    visitor: &V,
    a: Field,
    claimed: impl Fn(&Gate, &ConstantForm) -> Field,
) -> Visited<Visited<V::Output>>
where
    V: Visit<Result<CircuitVar, Refusal>>,
{
    fn one<const GATE: usize, V>(
        visitor: &V,
        a: Field,
        claimed: &impl Fn(&Gate, &ConstantForm) -> Field,
    ) -> (&'static str, Visited<V::Output>)
    where
        V: Visit<Result<CircuitVar, Refusal>>,
    {
        let gate = &GATES[GATE];
        let out = |form: usize| claimed(gate, &CONSTANT_FORMS[form]);
        let visited = constant_form_names()
            .into_iter()
            .zip([
                visitor.visit(&WithConstant::<GATE, 0> { a, out: out(0) }),
                visitor.visit(&WithConstant::<GATE, 1> { a, out: out(1) }),
                visitor.visit(&WithConstant::<GATE, 2> { a, out: out(2) }),
                visitor.visit(&WithConstant::<GATE, 3> { a, out: out(3) }),
            ])
            .collect();
        (gate.name, visited)
    }
    vec![
        one::<0, _>(visitor, a, &claimed),
        one::<1, _>(visitor, a, &claimed),
        one::<2, _>(visitor, a, &claimed),
        one::<3, _>(visitor, a, &claimed),
        one::<4, _>(visitor, a, &claimed),
        one::<5, _>(visitor, a, &claimed),
    ]
}

pub struct FoldOp {
    pub name: &'static str,
    pub rule: &'static str,
    pub apply: fn(&[Bool]) -> Result<Bool, CircuitError>,
    pub truth: fn(&[bool]) -> bool,
}

pub const FOLDS: [FoldOp; 2] = [
    FoldOp {
        name: "all",
        rule: "the output is whether all flags are set",
        apply: |flags| Bool::all(flags),
        truth: |flags| flags.iter().all(|flag| *flag),
    },
    FoldOp {
        name: "any",
        rule: "the output is whether any flag is set",
        apply: |flags| Bool::any(flags),
        truth: |flags| flags.iter().any(|flag| *flag),
    },
];

pub const ALL: usize = 0;
pub const ANY: usize = 1;

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Fold<const OP: usize, const N: usize> {
    pub flags: [Field; N],
    pub out: Field,
}

impl<const OP: usize, const N: usize> FoldCircuit<OP, N> {
    fn output(&self) -> Result<CircuitVar, CircuitError> {
        let flags = self.flags.iter().map(bit).collect::<Result<Vec<_>, _>>()?;
        Ok(CircuitVar::from((FOLDS[OP].apply)(&flags)?))
    }
}

impl<const OP: usize, const N: usize> Fixture<Result<CircuitVar, Refusal>> for Fold<OP, N> {
    fn computed(circuit: &FoldCircuit<OP, N>) -> Result<CircuitVar, Refusal> {
        outcome(circuit.output())
    }
}

impl<const OP: usize, const N: usize> Constraints for FoldCircuit<OP, N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.output()?.assert_equal(&self.out, FOLDS[OP].rule)
    }
}

/// Visits the `Fold<OP, N>` whose length is that of `flags`.
pub fn fold<const OP: usize, V>(visitor: &V, flags: &[Field], out: Field) -> V::Output
where
    V: Visit<Result<CircuitVar, Refusal>>,
{
    match *flags {
        [] => visitor.visit(&Fold::<OP, 0> { flags: [], out }),
        [a] => visitor.visit(&Fold::<OP, 1> { flags: [a], out }),
        [a, b] => visitor.visit(&Fold::<OP, 2> { flags: [a, b], out }),
        [a, b, c] => visitor.visit(&Fold::<OP, 3> {
            flags: [a, b, c],
            out,
        }),
        _ => panic!("fold fixtures hold at most 3 flags"),
    }
}

/// Visits both folds for every flag combination, claiming
/// `claimed(op, flags)`.
pub fn every_fold<V>(
    visitor: &V,
    combinations: &[(&'static str, &[bool])],
    claimed: impl Fn(&FoldOp, &[bool]) -> Field,
) -> Visited<Visited<V::Output>>
where
    V: Visit<Result<CircuitVar, Refusal>>,
{
    let run = |op: usize| {
        combinations
            .iter()
            .map(|(name, flags)| {
                let fields: Vec<Field> = flags.iter().map(|flag| Field::from(*flag)).collect();
                let out = claimed(&FOLDS[op], flags);
                let visited = match op {
                    ALL => fold::<ALL, V>(visitor, &fields, out),
                    _ => fold::<ANY, V>(visitor, &fields, out),
                };
                (*name, visited)
            })
            .collect()
    };
    vec![(FOLDS[ALL].name, run(ALL)), (FOLDS[ANY].name, run(ANY))]
}

type SelectForm = fn(&Bool, &Bool, &Bool) -> Bool;

pub const SELECT_FORMS: [(&str, SelectForm); 2] = [
    ("condition.select(t, f)", |c, t, f| c.select(t, f)),
    ("<Bool as Select>::select(c, t, f)", |c, t, f| {
        <Bool as Select>::select(c, t, f)
    }),
];

pub fn select_form_names() -> Vec<&'static str> {
    SELECT_FORMS.iter().map(|(name, _)| *name).collect()
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Choose<const FORM: usize> {
    pub condition: Field,
    pub if_true: Field,
    pub if_false: Field,
    pub out: Field,
}

impl<const FORM: usize> ChooseCircuit<FORM> {
    fn output(&self) -> Result<CircuitVar, CircuitError> {
        let (_, form) = SELECT_FORMS[FORM];
        let condition = bit(&self.condition)?;
        let (if_true, if_false) = (bit(&self.if_true)?, bit(&self.if_false)?);
        Ok(CircuitVar::from(form(&condition, &if_true, &if_false)))
    }
}

impl<const FORM: usize> Fixture<Result<CircuitVar, Refusal>> for Choose<FORM> {
    fn computed(circuit: &ChooseCircuit<FORM>) -> Result<CircuitVar, Refusal> {
        outcome(circuit.output())
    }
}

impl<const FORM: usize> Constraints for ChooseCircuit<FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.output()?.assert_equal(&self.out, SELECT_RULE)
    }
}

pub fn select_forms<V: Visit<Result<CircuitVar, Refusal>>>(
    visitor: &V,
    (condition, if_true, if_false, out): (Field, Field, Field, Field),
) -> Visited<V::Output> {
    select_form_names()
        .into_iter()
        .zip([
            visitor.visit(&Choose::<0> {
                condition,
                if_true,
                if_false,
                out,
            }),
            visitor.visit(&Choose::<1> {
                condition,
                if_true,
                if_false,
                out,
            }),
        ])
        .collect()
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ChooseConstantCondition<const K: bool> {
    pub if_true: Field,
    pub if_false: Field,
    pub out: Field,
}

impl<const K: bool> Constraints for ChooseConstantConditionCircuit<K> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let (if_true, if_false) = (bit(&self.if_true)?, bit(&self.if_false)?);
        CircuitVar::from(Bool::constant(K).select(&if_true, &if_false))
            .assert_equal(&self.out, SELECT_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ChooseConstantBranches<const T: bool, const F: bool> {
    pub condition: Field,
    pub out: Field,
}

impl<const T: bool, const F: bool> Constraints for ChooseConstantBranchesCircuit<T, F> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let condition = bit(&self.condition)?;
        CircuitVar::from(condition.select(&Bool::constant(T), &Bool::constant(F)))
            .assert_equal(&self.out, SELECT_RULE)
    }
}

pub struct AssertOp<Apply> {
    pub name: &'static str,
    pub rule: &'static str,
    pub apply: Apply,
}

type UnaryAssert = fn(&Bool, &'static str) -> Result<(), CircuitError>;
type BinaryAssert = fn(&Bool, &Bool, &'static str) -> Result<(), CircuitError>;

/// `holds` is indexed by a.
pub const UNARY_ASSERTS: [(AssertOp<UnaryAssert>, [bool; 2]); 2] = [
    (
        AssertOp {
            name: "assert_true",
            rule: "a is true",
            apply: |a, rule| a.assert_true(rule),
        },
        [false, true],
    ),
    (
        AssertOp {
            name: "assert_false",
            rule: "a is false",
            apply: |a, rule| a.assert_false(rule),
        },
        [true, false],
    ),
];

/// `holds` is indexed as a gate's truth table, by (a, b).
pub const BINARY_ASSERTS: [(AssertOp<BinaryAssert>, [bool; 4]); 3] = [
    (
        AssertOp {
            name: "a.assert_true_if(b)",
            rule: "a is true if b is",
            apply: |a, b, rule| a.assert_true_if(b, rule),
        },
        [true, false, true, true],
    ),
    (
        AssertOp {
            name: "assert_equal",
            rule: "a equals b",
            apply: |a, b, rule| a.assert_equal(b, rule),
        },
        [true, false, false, true],
    ),
    (
        AssertOp {
            name: "assert_not_equal",
            rule: "a differs from b",
            apply: |a, b, rule| a.assert_not_equal(b, rule),
        },
        [false, true, true, false],
    ),
];

pub const ASSERT_NOT_EQUAL: usize = 2;

pub fn unary_assert_names() -> Vec<&'static str> {
    UNARY_ASSERTS.iter().map(|(op, _)| op.name).collect()
}

pub fn binary_assert_names() -> Vec<&'static str> {
    BINARY_ASSERTS.iter().map(|(op, _)| op.name).collect()
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertedUnary<const OP: usize> {
    pub a: Field,
}

impl<const OP: usize> Constraints for AssertedUnaryCircuit<OP> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let (op, _) = &UNARY_ASSERTS[OP];
        (op.apply)(&bit(&self.a)?, op.rule)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertedBinary<const OP: usize> {
    pub a: Field,
    pub b: Field,
}

impl<const OP: usize> Constraints for AssertedBinaryCircuit<OP> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let (op, _) = &BINARY_ASSERTS[OP];
        (op.apply)(&bit(&self.a)?, &bit(&self.b)?, op.rule)
    }
}

pub fn unary_asserts<V: Visit>(visitor: &V, a: Field) -> Visited<V::Output> {
    unary_assert_names()
        .into_iter()
        .zip([
            visitor.visit(&AssertedUnary::<0> { a }),
            visitor.visit(&AssertedUnary::<1> { a }),
        ])
        .collect()
}

pub fn binary_asserts<V: Visit>(visitor: &V, (a, b): (Field, Field)) -> Visited<V::Output> {
    binary_assert_names()
        .into_iter()
        .zip([
            visitor.visit(&AssertedBinary::<0> { a, b }),
            visitor.visit(&AssertedBinary::<1> { a, b }),
            visitor.visit(&AssertedBinary::<2> { a, b }),
        ])
        .collect()
}

pub const ASSERT_EQUAL_IF_RULE: &str = "a equals b if the condition is true";

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertEqualIf {
    pub a: Field,
    pub b: Field,
    pub condition: Field,
}

impl Constraints for AssertEqualIfCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let (a, b, condition) = (bit(&self.a)?, bit(&self.b)?, bit(&self.condition)?);
        a.assert_equal_if(&b, &condition, ASSERT_EQUAL_IF_RULE)
    }
}

pub const ASSERT_TRUE_IF_RULE: &str = "the flag is true if the condition is";

pub struct AssertTrueIfForm {
    pub name: &'static str,
    /// `Some(k)` when the flag is the constant k and x the condition,
    /// `None` when x is the flag.
    pub flag: Option<bool>,
    pub condition: Option<bool>,
}

pub const ASSERT_TRUE_IF_FORMS: [AssertTrueIfForm; 4] = [
    AssertTrueIfForm {
        name: "x.assert_true_if(false)",
        flag: None,
        condition: Some(false),
    },
    AssertTrueIfForm {
        name: "x.assert_true_if(true)",
        flag: None,
        condition: Some(true),
    },
    AssertTrueIfForm {
        name: "false.assert_true_if(x)",
        flag: Some(false),
        condition: None,
    },
    AssertTrueIfForm {
        name: "true.assert_true_if(x)",
        flag: Some(true),
        condition: None,
    },
];

impl AssertTrueIfForm {
    pub fn holds(&self, x: bool) -> bool {
        let flag = self.flag.unwrap_or(x);
        let condition = self.condition.unwrap_or(x);
        flag || !condition
    }
}

pub fn assert_true_if_form_names() -> Vec<&'static str> {
    ASSERT_TRUE_IF_FORMS.iter().map(|form| form.name).collect()
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertTrueIfConstant<const FORM: usize> {
    pub x: Field,
}

impl<const FORM: usize> Constraints for AssertTrueIfConstantCircuit<FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let form = &ASSERT_TRUE_IF_FORMS[FORM];
        let x = bit(&self.x)?;
        let flag = form.flag.map(Bool::constant).unwrap_or_else(|| x.clone());
        let condition = form.condition.map(Bool::constant).unwrap_or(x);
        flag.assert_true_if(&condition, ASSERT_TRUE_IF_RULE)
    }
}

pub fn assert_true_if_forms<V: Visit>(visitor: &V, x: Field) -> Visited<V::Output> {
    assert_true_if_form_names()
        .into_iter()
        .zip([
            visitor.visit(&AssertTrueIfConstant::<0> { x }),
            visitor.visit(&AssertTrueIfConstant::<1> { x }),
            visitor.visit(&AssertTrueIfConstant::<2> { x }),
            visitor.visit(&AssertTrueIfConstant::<3> { x }),
        ])
        .collect()
}

/// Every `Bool` operation on constants only, with every assertion holding.
#[derive(Clone, Copy, Debug)]
pub struct Constants;

#[derive(Clone, Debug)]
pub struct ConstantsCircuit;

impl CircuitType for ConstantsCircuit {}

impl ProofInput for Constants {
    type Circuit = ConstantsCircuit;

    fn instantiate(&self, _allocator: &Allocator) -> Result<ConstantsCircuit, CircuitError> {
        Ok(ConstantsCircuit)
    }
}

impl Placeholder for Constants {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self)
    }
}

impl Constraints for ConstantsCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let bits = [Bool::constant(false), Bool::constant(true)];
        for a in &bits {
            let _ = a.not();
            let _ = Bool::try_from(CircuitVar::from(a.clone()))?;
            let _ = Uint::<64>::from(a.clone());
            for b in &bits {
                for gate in &GATES {
                    let _ = (gate.apply)(a, b)?;
                }
                for c in &bits {
                    let _ = a.select(b, c);
                }
                let _ = Bool::all(&[a.clone(), b.clone()])?;
                let _ = Bool::any(&[a.clone(), b.clone(), a.clone()])?;
            }
            a.assert_equal(a, "a constant equals itself")?;
            a.assert_not_equal(&a.not(), "a constant differs from its negation")?;
            a.assert_true_if(a, "a constant is true if it is")?;
            a.assert_equal_if(&a.not(), &Bool::constant(false), "skipped")?;
        }
        Bool::constant(true).assert_true("true is true")?;
        Bool::constant(false).assert_false("false is false")
    }
}

/// A converted variable combined only with constants, asserting nothing.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Linear {
    pub a: Field,
}

impl Constraints for LinearCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let a = bit(&self.a)?;
        let bits = [Bool::constant(false), Bool::constant(true)];
        let _ = a.not();
        let _ = Uint::<64>::from(a.clone());
        let _ = Bool::all(std::slice::from_ref(&a))?;
        let _ = Bool::any(std::slice::from_ref(&a))?;
        for k in &bits {
            for gate in &GATES {
                let _ = (gate.apply)(&a, k)?;
                let _ = (gate.apply)(k, &a)?;
            }
            let _ = k.select(&a, &a.not());
            let _ = a.select(k, &k.not());
        }
        Ok(())
    }
}
