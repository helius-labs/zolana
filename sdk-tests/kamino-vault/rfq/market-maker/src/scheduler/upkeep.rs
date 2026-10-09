use super::{max_outputs_for, select_smallest, Selection};
use crate::tracker::TrackedUtxo;

pub enum Upkeep {
    Consolidate(Selection),
    Split { selection: Selection, parts: usize },
}

pub struct UpkeepPolicy {
    pub base_lanes: usize,
    pub min_lane_value: u64,
}

impl UpkeepPolicy {
    pub fn target_lanes(&self, balance: u64) -> usize {
        let by_value = usize::try_from(balance / self.min_lane_value.max(1)).unwrap_or(usize::MAX);
        self.base_lanes.min(by_value).max(1)
    }

    pub fn consolidate_parts(&self, value: u64, inputs: usize) -> usize {
        self.target_lanes(value).min(max_outputs_for(inputs)).max(1)
    }

    pub fn plan(&self, lanes: &[TrackedUtxo]) -> Option<Upkeep> {
        let lanes: Vec<TrackedUtxo> = lanes
            .iter()
            .filter(|utxo| utxo.amount() > 0)
            .cloned()
            .collect();
        let balance: u64 = lanes.iter().map(TrackedUtxo::amount).sum();
        let target = self.target_lanes(balance);
        let count = lanes.len();
        if count > target {
            let selection = select_smallest(&lanes, count - target + 1);
            return (selection.inputs.len() >= 2).then_some(Upkeep::Consolidate(selection));
        }
        if count < target {
            return self.split(&lanes, count, target);
        }
        None
    }

    fn split(&self, lanes: &[TrackedUtxo], count: usize, target: usize) -> Option<Upkeep> {
        let largest = lanes.iter().max_by_key(|utxo| utxo.amount())?;
        let by_value =
            usize::try_from(largest.amount() / self.min_lane_value.max(1)).unwrap_or(usize::MAX);
        let parts = (target - count + 1).min(max_outputs_for(1)).min(by_value);
        if parts < 2 {
            return None;
        }
        Selection::single(largest).map(|selection| Upkeep::Split { selection, parts })
    }
}
