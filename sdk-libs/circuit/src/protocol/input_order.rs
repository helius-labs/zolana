use alloc::vec::Vec;
use super::SpentInput;

pub(super) fn ordered_inputs(mut inputs: Vec<(SpentInput, bool)>) -> Vec<SpentInput> {
    for end in (1..inputs.len()).rev() {
        for i in 0..end {
            let left = inputs[i];
            let right = inputs[i + 1];
            let swap = left.1 & !right.1;
            if swap { inputs[i].0 = right.0; inputs[i + 1].0 = left.0; }
            // Update the sorting keys directly, avoiding nested conditional keys.
            inputs[i].1 = left.1 & right.1;
            inputs[i + 1].1 = left.1 | right.1;
        }
    }
    inputs.into_iter().map(|(input, _)| input).collect()
}
