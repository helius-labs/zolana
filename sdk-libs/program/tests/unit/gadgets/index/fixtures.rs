use zolana_program::{
    circuit::{one_hot, select_index, Assert, CircuitVar, Constraints, Field},
    conversion::ProofInput,
    CircuitError,
};

pub const FLAG_RULE: &str = "the decoded flags match the index";
pub const SELECT_RULE: &str = "the selected item matches the index";

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct OneHot<const N: usize> {
    pub index: Field,
    pub flags: [Field; N],
}
impl<const N: usize> Constraints for OneHotCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let flags = one_hot::<N>(&self.index)?;
        for (flag, claimed) in flags.into_iter().zip(&self.flags) {
            CircuitVar::from(flag).assert_equal(claimed, FLAG_RULE)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct SelectIndex<const N: usize> {
    pub items: [Field; N],
    pub index: Field,
    pub selected: Field,
}
impl<const N: usize> Constraints for SelectIndexCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        select_index(&self.items, &self.index)?.assert_equal(&self.selected, SELECT_RULE)
    }
}

pub fn decoded<const N: usize>(index: usize) -> OneHot<N> {
    OneHot {
        index: Field::from(index as u64),
        flags: std::array::from_fn(|position| Field::from(position == index)),
    }
}

pub fn selected<const N: usize>(items: [Field; N], index: usize) -> SelectIndex<N> {
    SelectIndex {
        items,
        index: Field::from(index as u64),
        selected: *items.get(index).expect("a valid test index"),
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ConstantIndex {
    pub flags: [Field; 3],
    pub selected: Field,
}
impl Constraints for ConstantIndexCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let index = zolana_program::circuit::constant(1u64);
        for (flag, claimed) in one_hot::<3>(&index)?.into_iter().zip(&self.flags) {
            CircuitVar::from(flag).assert_equal(claimed, FLAG_RULE)?;
        }
        let items = [3u64, 5, 7].map(zolana_program::circuit::constant);
        select_index(&items, &index)?.assert_equal(&self.selected, SELECT_RULE)
    }
}
