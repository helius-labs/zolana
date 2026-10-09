use std::time::Instant;

use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use tokio::sync::oneshot;
use zolana_keypair::ShieldedKeypair;

use k_lend_rfq_sdk::swap::Fill;

use crate::{
    api::Inner,
    error::MakerError,
    transactions::{
        confirm::Retry,
        coordinator::{Coordinator, Event},
        steps::StepState,
    },
};

impl Inner {
    pub async fn settle(
        &self,
        fill: &Fill,
        user_signature: Signature,
    ) -> Result<Signature, MakerError> {
        let (reply, receipt) = oneshot::channel();
        self.runtime
            .events
            .send(Event::Settle {
                message: fill.message.clone(),
                user_signature,
                reply,
            })
            .map_err(|_| MakerError::ShuttingDown)?;
        receipt.await.map_err(|_| MakerError::CoordinatorStopped)?
    }
}

impl Coordinator {
    pub async fn on_settle(
        &mut self,
        message: &VersionedMessage,
        user_signature: Signature,
        reply: oneshot::Sender<Result<Signature, MakerError>>,
    ) {
        let Some(id) = self.steps.find_fill(message) else {
            let _ = reply.send(Err(MakerError::UnknownFill));
            return;
        };
        let Some(step) = self.steps.get_mut(id) else {
            let _ = reply.send(Err(MakerError::UnknownFill));
            return;
        };
        if step.state != StepState::AwaitingSignature {
            let _ = reply.send(Err(MakerError::AlreadySettling { step: id }));
            return;
        }
        let Some(fill) = step.fill.as_mut() else {
            let _ = reply.send(Err(MakerError::UnknownFill));
            return;
        };
        if fill
            .expires_at
            .is_none_or(|deadline| Instant::now() >= deadline)
        {
            let _ = reply.send(Err(MakerError::ReservationExpired { step: id }));
            self.discard(id, MakerError::ReservationExpired { step: id }, Retry::Fail)
                .await;
            self.try_schedule().await;
            return;
        }
        let Some(message) = fill.message.clone() else {
            let _ = reply.send(Err(MakerError::UnknownFill));
            return;
        };
        match co_sign(&self.identity.keys, message, user_signature) {
            Ok(transaction) => {
                fill.transaction = Some(transaction);
                fill.settle = Some(reply);
                self.spawn_send(id);
            }
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
    }
}

fn co_sign(
    keys: &ShieldedKeypair,
    message: VersionedMessage,
    user_signature: Signature,
) -> Result<VersionedTransaction, MakerError> {
    let payer = keys.pubkey();
    let required = usize::from(message.header().num_required_signatures);
    let accounts = message.static_account_keys();
    let signers = accounts
        .get(..required)
        .ok_or(MakerError::MalformedMessage {
            required,
            accounts: accounts.len(),
        })?
        .to_vec();
    let (maker, users): (Vec<Address>, Vec<Address>) =
        signers.iter().partition(|signer| **signer == payer);
    if maker.is_empty() {
        return Err(MakerError::UnsignedMessage);
    }
    if let Some(extra) = users.get(1) {
        return Err(MakerError::UnexpectedSigner { signer: *extra });
    }
    let serialized = message.serialize();
    let maker_signature =
        keys.try_sign_message(&serialized)
            .map_err(|source| MakerError::Signer {
                pubkey: payer,
                source,
            })?;
    let signatures = signers
        .iter()
        .map(|signer| {
            if *signer == payer {
                maker_signature
            } else {
                user_signature
            }
        })
        .collect();
    Ok(VersionedTransaction {
        signatures,
        message,
    })
}
