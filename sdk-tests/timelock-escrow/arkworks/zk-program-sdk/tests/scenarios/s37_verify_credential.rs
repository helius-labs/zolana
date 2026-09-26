use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::right_align;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s35_create_issuer::Credential,
    shared::{data_hash, data_input, keypair, poseidon_bytes},
};

#[derive(Clone)]
struct VerifyCredential {
    private: VerifyCredentialPrivateInputs,
    public: VerifyCredentialPublicInputs,
}

#[derive(Clone)]
struct VerifyCredentialPrivateInputs {
    tx_context: TxContext,
    credential_utxo: WalletUtxo,
    credential: Credential,
    attribute: u64,
    salt: [u8; 32],
    secret: [u8; 32],
}

#[derive(Clone)]
struct VerifyCredentialPublicInputs {
    issuer: ShieldedAddress,
    verification_id: u64,
    nullifier: [u8; 32],
    threshold: u64,
}

impl zk_program_sdk::circuit::CircuitType for circuit::VerifyCredential {}

impl ProofInput for VerifyCredential {
    type Circuit = circuit::VerifyCredential;

    fn instantiate(
        &self,
        allocator: &Allocator,
    ) -> Result<circuit::VerifyCredential, RelationError> {
        let private = &self.private;
        let public = &self.public;
        Ok(circuit::VerifyCredential {
            private: circuit::VerifyCredentialPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                credential_utxo: private.credential_utxo.instantiate(allocator)?,
                credential: private.credential.instantiate(allocator)?,
                attribute: private.attribute.instantiate(allocator)?,
                salt: private.salt.instantiate(allocator)?,
                secret: private.secret.instantiate(allocator)?,
            },
            public: circuit::VerifyCredentialPublicInputs {
                issuer: public.issuer.instantiate(allocator)?,
                verification_id: public.verification_id.instantiate(allocator)?,
                nullifier: public.nullifier.instantiate(allocator)?,
                threshold: public.threshold.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for VerifyCredential {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: VerifyCredentialPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                credential_utxo: Placeholder::placeholder()?,
                credential: Placeholder::placeholder()?,
                attribute: Placeholder::placeholder()?,
                salt: Placeholder::placeholder()?,
                secret: Placeholder::placeholder()?,
            },
            public: VerifyCredentialPublicInputs {
                issuer: Placeholder::placeholder()?,
                verification_id: Placeholder::placeholder()?,
                nullifier: Placeholder::placeholder()?,
                threshold: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            poseidon, Assert, Bits, CheckedTransaction, Circuit, CircuitMarker, CircuitVar,
            ConfidentialTransaction, DataHash, DataUtxo, Owner, PublicInputs, TxContext, Utxo,
        },
        RelationError,
    };

    use crate::s35_create_issuer::circuit::Credential;

    pub struct VerifyCredential {
        pub private: VerifyCredentialPrivateInputs,
        pub public: VerifyCredentialPublicInputs,
    }

    pub struct VerifyCredentialPrivateInputs {
        pub tx_context: TxContext,
        pub credential_utxo: Utxo,
        pub credential: Credential,
        pub attribute: CircuitVar,
        pub salt: CircuitVar,
        pub secret: CircuitVar,
    }

    pub struct VerifyCredentialPublicInputs {
        pub issuer: Owner,
        pub verification_id: CircuitVar,
        pub nullifier: CircuitVar,
        pub threshold: CircuitVar,
    }

    impl Circuit for VerifyCredential {
        const MARKER: CircuitMarker = CircuitMarker;

        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let public = &self.public;
            let credential = DataUtxo::new_mut(&private.credential_utxo, &private.credential)?;
            credential
                .issuer_hash
                .assert_equal(&public.issuer.hash()?, "the credential is another issuer's")?;
            poseidon(&[private.attribute.clone(), private.salt.clone()])?.assert_equal(
                &credential.attribute_commitment,
                "the attribute is not the committed one",
            )?;
            (private.attribute.clone() - &public.threshold).check_bits(64)?;
            poseidon(&[
                public.verification_id.clone(),
                private.secret.clone(),
                DataHash::hash(&*credential)?,
            ])?
            .assert_equal(&public.nullifier, "the nullifier is not the credential's")?;

            ConfidentialTransaction::new(&private.tx_context, public)
                .with_data_utxo(credential)
                .check()
        }
    }

    impl PublicInputs for VerifyCredentialPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[
                self.issuer.hash()?,
                self.verification_id.clone(),
                self.nullifier.clone(),
                self.threshold.clone(),
                transaction_hash.clone(),
            ])
        }
    }
}

#[test]
fn verify_credential_prove_and_verify() {
    let issuer = keypair(5).shielded_address().expect("issuer address");
    let user = keypair(6);
    let address = user.shielded_address().expect("user address");
    let payer = address.solana_address().expect("payer");
    let salt = [3u8; 32];
    let secret = [9u8; 32];
    let credential = Credential {
        issuer_hash: issuer.owner_hash().expect("issuer hash"),
        attribute_commitment: poseidon_bytes(&[right_align(&21u64.to_be_bytes()), salt]),
    };
    let credential_utxo = data_input(&user, 0, &credential, 0);
    let nullifier = poseidon_bytes(&[
        right_align(&77u64.to_be_bytes()),
        secret,
        data_hash(&credential),
    ]);

    let verify = VerifyCredential {
        private: VerifyCredentialPrivateInputs {
            tx_context: TxContext::new(),
            credential_utxo,
            credential: credential.clone(),
            attribute: 21,
            salt,
            secret,
        },
        public: VerifyCredentialPublicInputs {
            issuer,
            verification_id: 77,
            nullifier,
            threshold: 18,
        },
    };
    let spp_proof_inputs = verify
        .create_proof_inputs_and_encrypt(&user, payer, u64::MAX)
        .expect("verify credential proof inputs");
    assert_eq!(
        spp_proof_inputs
            .output_utxos
            .iter()
            .map(|output| (
                output.owner_address,
                output.asset,
                output.amount,
                output.data.utxo_data().map(<[u8]>::to_vec),
            ))
            .collect::<Vec<_>>(),
        vec![(
            Some(address),
            Mint::SOL,
            0,
            Some(borsh::to_vec(&credential).expect("credential bytes")),
        )]
    );

    let prover =
        Groth16Prover::<VerifyCredential>::new_with_test_setup().expect("verify credential setup");
    let result = prove(&prover, &verify, "verify credential proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
