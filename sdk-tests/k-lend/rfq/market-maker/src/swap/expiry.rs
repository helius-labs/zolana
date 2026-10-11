use std::time::Instant;

use crate::{
    error::MakerError,
    transactions::{
        confirm::Retry,
        coordinator::{Coordinator, Event},
        steps::{StepId, StepState},
    },
};

impl Coordinator {
    pub fn spawn_expiry(&self, id: StepId, expires_at: Instant) {
        let events = self.runtime.events.clone();
        let cancel = self.runtime.cancel.clone();
        self.runtime.tasks.spawn(async move {
            let deadline = tokio::time::sleep_until(expires_at.into());
            if cancel.run_until_cancelled(deadline).await.is_some() {
                let _ = events.send(Event::Expire(id));
            }
        });
    }

    pub async fn on_expire(&mut self, id: StepId) {
        let expired = self.steps.get(id).is_some_and(|step| {
            step.state == StepState::AwaitingSignature
                && step
                    .fill
                    .as_ref()
                    .and_then(|fill| fill.expires_at)
                    .is_some_and(|deadline| Instant::now() >= deadline)
        });
        if expired {
            self.abort(id, MakerError::ReservationExpired { step: id }, Retry::Fail)
                .await;
        }
    }
}
