//! `requestCreateViewingKeyAccount`: build the key-encryption proof and the
//! `create_viewing_key_account` instruction. The backend mints a fresh shared
//! viewing key and nullifier secret, encrypts the shared key to the caller's
//! recovery keys (only when `owner_signature` is present) and always to the
//! auditor key, and returns the instruction for a smart account to wrap.

use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_pubkey::Pubkey;
use zolana_client::Rpc;
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::{
    constants::{OWNER_KIND_KEYPAIR, OWNER_KIND_SMART_ACCOUNT},
    instruction::builders::CreateViewingKeyAccount,
    PROGRAM_ID_PUBKEY, VIEWING_KEY_ACCOUNT_PDA_SEED,
};
use zolana_squads_sdk::prover::{prove_create_viewing_key_account, KeyEncryptionWitness};
use zolana_transaction::Address;

use crate::{
    backend::SquadsBackend,
    error::{Result, SquadsBackendError},
    types::{RequestCreateViewingKeyAccountRequest, RequestCreateViewingKeyAccountResponse},
};

impl<I: Rpc, R: Rpc> SquadsBackend<I, R> {
    /// Build the key-encryption proof and `create_viewing_key_account` instruction.
    ///
    /// The mock returns the built instruction (the smart-account path); a keypair
    /// owner's auto-send path is left to the caller.
    pub fn request_create_viewing_key_account(
        &self,
        request: RequestCreateViewingKeyAccountRequest,
    ) -> Result<RequestCreateViewingKeyAccountResponse> {
        // Recovery keys are only registered when the owner signs; an auditor-only
        // account carries none (spec: `requestCreateViewingKeyAccount`).
        let recovery_keys: Vec<P256Pubkey> = if request.owner_signature.is_some() {
            request
                .recovery_keys
                .iter()
                .map(|k| {
                    P256Pubkey::from_bytes(*k)
                        .map_err(|e| SquadsBackendError::Keypair(format!("{e:?}")))
                })
                .collect::<Result<_>>()?
        } else {
            Vec::new()
        };
        let recovery_count = recovery_keys.len();

        let auditor_pk = P256Pubkey::from_p256(&self.auditor_public_key());
        let mut recipient_keys = recovery_keys;
        recipient_keys.push(auditor_pk);

        if request.owner_kind != OWNER_KIND_KEYPAIR
            && request.owner_kind != OWNER_KIND_SMART_ACCOUNT
        {
            return Err(SquadsBackendError::InvalidOwnerKind(request.owner_kind));
        }

        let witness = KeyEncryptionWitness {
            viewing_secret_key: SecretKey::random(&mut OsRng),
            ephemeral_secret_key: SecretKey::random(&mut OsRng),
            nullifier_secret: random_field_element(),
            recipient_keys,
            old_state_hash: [0u8; 32],
        };

        let (mut ix_data, _result) =
            prove_create_viewing_key_account(witness, recovery_count, self.prover_url())?;
        ix_data.owner_kind = request.owner_kind;

        let owner = Pubkey::new_from_array(request.owner.to_bytes());
        let (viewing_key_account, _bump) = Pubkey::find_program_address(
            &[
                VIEWING_KEY_ACCOUNT_PDA_SEED,
                request.owner.to_bytes().as_ref(),
            ],
            &PROGRAM_ID_PUBKEY,
        );

        let instruction = CreateViewingKeyAccount {
            fee_payer: self.zone_authority_pubkey(),
            owner,
            owner_signs: request.owner_signature.is_some(),
            viewing_key_account,
            zone_config: Pubkey::new_from_array(self.zone_config().to_bytes()),
            system_program: Pubkey::default(),
            data: ix_data,
        }
        .instruction();

        Ok(RequestCreateViewingKeyAccountResponse::Instruction {
            viewing_key_account: Address::new_from_array(viewing_key_account.to_bytes()),
            instruction,
        })
    }
}

/// A random 32-byte value in the BN254 field range (top byte cleared). The
/// nullifier secret is a BN254 field element by design; the ephemeral and
/// viewing secrets are full-range P-256 scalars.
fn random_field_element() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(SecretKey::random(&mut OsRng).to_bytes().as_slice());
    bytes[0] = 0;
    bytes
}
