//! The backend mints a fresh shared viewing key and nullifier secret and
//! encrypts the shared key to the caller's auditor key. The backend's
//! configured ring co-signer authenticates enrollment on-chain. The proof
//! owner field is a separate identity that does not sign. Recovery enrollment
//! fails closed until the instruction can verify a signature from an authority
//! cryptographically bound to that identity.

use p256::{elliptic_curve::rand_core::OsRng, SecretKey};
use solana_pubkey::Pubkey;
use zolana_client::Rpc;
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::{
    constants::{OWNER_KIND_KEYPAIR, OWNER_KIND_SMART_ACCOUNT},
    instruction::builders::CreateViewingKeyAccount,
    PROGRAM_ID_PUBKEY, VIEWING_KEY_ACCOUNT_PDA_SEED,
};
use zolana_squads_sdk::prover::{prove_create_viewing_key_account, KeyEncryptionProofInputs};
use zolana_transaction::Address;

use crate::{
    authorization::ReadAuthorization,
    backend::SquadsBackend,
    convert::to_pubkey,
    error::{Result, SquadsBackendError},
    types::{RequestCreateViewingKeyAccountRequest, RequestCreateViewingKeyAccountResponse},
};

impl<I: Rpc, R: Rpc, A: ReadAuthorization> SquadsBackend<I, R, A> {
    /// The mock returns the built instruction (the smart-account path). A
    /// keypair owner's auto-send path is left to the caller.
    pub fn request_create_viewing_key_account(
        &self,
        request: RequestCreateViewingKeyAccountRequest,
    ) -> Result<RequestCreateViewingKeyAccountResponse> {
        // `owner_signature` has no public key or signed-message binding in this
        // request, so checking only its presence would let the ring co-signer add
        // arbitrary recovery keys. The stored owner is usually a derived proof
        // identity and cannot sign as a Solana account either. Reject instead of
        // silently dropping or trusting unverifiable authorization.
        if !request.recovery_keys.is_empty() || request.owner_signature.is_some() {
            return Err(SquadsBackendError::Unsupported(
                "recovery-key enrollment requires a versioned owner-authentication path".into(),
            ));
        }
        let recovery_count = 0;

        let auditor_pk = P256Pubkey::from_p256(&self.auditor_public_key());
        let recipient_keys = vec![auditor_pk];

        if request.owner_kind != OWNER_KIND_KEYPAIR
            && request.owner_kind != OWNER_KIND_SMART_ACCOUNT
        {
            return Err(SquadsBackendError::InvalidOwnerKind(request.owner_kind));
        }

        let proof_inputs = KeyEncryptionProofInputs {
            viewing_secret_key: SecretKey::random(&mut OsRng),
            ephemeral_secret_key: SecretKey::random(&mut OsRng),
            nullifier_secret: random_field_element(),
            recipient_keys,
            old_state_hash: [0u8; 32],
        };

        let (mut ix_data, _result) =
            prove_create_viewing_key_account(proof_inputs, recovery_count, self.prover_url())?;
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
            enrollment_authority: to_pubkey(self.ring_authority_address()),
            owner_identity: owner,
            viewing_key_account,
            ring_config: Pubkey::new_from_array(self.ring_config().to_bytes()),
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
/// nullifier secret is a BN254 field element by design. The ephemeral and
/// viewing secrets are full-range P-256 scalars.
fn random_field_element() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(SecretKey::random(&mut OsRng).to_bytes().as_slice());
    bytes[0] = 0;
    bytes
}
