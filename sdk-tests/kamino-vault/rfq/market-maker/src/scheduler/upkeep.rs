use super::{max_outputs_for, profile::LaneProfile, select_smallest, Selection};
use crate::tracker::TrackedUtxo;

pub struct Upkeep {
    pub selection: Selection,
    pub parts: Vec<u64>,
}

pub struct UpkeepPolicy<'a> {
    pub profile: &'a LaneProfile,
    pub max_inputs: usize,
}

impl UpkeepPolicy<'_> {
    pub fn plan(&self, lanes: &[TrackedUtxo]) -> Option<Upkeep> {
        let lanes: Vec<TrackedUtxo> = lanes
            .iter()
            .filter(|utxo| utxo.amount() > 0)
            .cloned()
            .collect();
        let amounts: Vec<u64> = lanes.iter().map(TrackedUtxo::amount).collect();
        let balance: u64 = amounts.iter().sum();
        let surplus = self.profile.surplus_lanes(balance, &amounts);
        if surplus > 0 {
            return self.merge(&lanes, surplus);
        }
        if self.profile.missing(balance, &amounts).is_empty() {
            return None;
        }
        self.split(&lanes)
    }

    fn merge(&self, lanes: &[TrackedUtxo], surplus: usize) -> Option<Upkeep> {
        let selection = select_smallest(lanes, (surplus + 1).min(self.max_inputs));
        let inputs = selection.inputs.len();
        if inputs < 2 {
            return None;
        }
        let others = others(lanes, &selection);
        let max_parts = inputs.saturating_sub(surplus).min(max_outputs_for(inputs));
        let parts = self.profile.parts(selection.total, &others, max_parts);
        Some(Upkeep { selection, parts })
    }

    fn split(&self, lanes: &[TrackedUtxo]) -> Option<Upkeep> {
        let amounts: Vec<u64> = lanes.iter().map(TrackedUtxo::amount).collect();
        let (index, parts) = self.profile.split(&amounts, max_outputs_for(1))?;
        let selection = Selection::single(lanes.get(index)?)?;
        Some(Upkeep { selection, parts })
    }
}

fn others(lanes: &[TrackedUtxo], selection: &Selection) -> Vec<u64> {
    let selected = selection.hashes();
    lanes
        .iter()
        .filter(|utxo| !selected.contains(&utxo.utxo_hash()))
        .map(TrackedUtxo::amount)
        .collect()
}
