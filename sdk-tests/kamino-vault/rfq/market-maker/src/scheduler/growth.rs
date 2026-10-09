use super::max_outputs_for;

#[derive(Clone, Copy, Debug)]
pub struct Growth {
    pub queued: usize,
    pub free_lanes: usize,
    pub tracked_lanes: usize,
    pub max_lanes: usize,
    pub inputs: usize,
    pub change: u64,
    pub min_lane_value: u64,
    pub max_outputs: usize,
}

impl Growth {
    pub fn change_outputs(self) -> usize {
        let backlogged = self.queued > self.free_lanes;
        if self.change == 0 || !backlogged {
            return 1;
        }
        let room = (self.max_lanes + self.inputs).saturating_sub(self.tracked_lanes);
        let by_value =
            usize::try_from(self.change / self.min_lane_value.max(1)).unwrap_or(usize::MAX);
        let by_shape = max_outputs_for(self.inputs)
            .min(self.max_outputs)
            .saturating_sub(1);
        room.min(by_value).min(by_shape).max(1)
    }
}
