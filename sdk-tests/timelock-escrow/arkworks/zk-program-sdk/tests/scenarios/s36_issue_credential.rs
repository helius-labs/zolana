use zk_program_sdk::{
    conversion::{Allocator, Placeholder, ProofInput},
    Groth16Prover, RelationError, TxContext, ZkProgram,
};
use zolana_hasher::primitives::right_align;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

use crate::{
    benchmark::prove,
    s35_create_issuer::{Credential, Issuer},
    shared::{data_input, keypair, poseidon_bytes},
};

#[derive(Clone)]
struct IssueCredential {
    private: IssueCredentialPrivateInputs,
    public: IssueCredentialPublicInputs,
}

#[derive(Clone)]
struct IssueCredentialPrivateInputs {
    tx_context: TxContext,
    issuer_utxo: WalletUtxo,
    issuer_state: Issuer,
    user: ShieldedAddress,
    attribute: u64,
    salt: [u8; 32],
}

#[derive(Clone)]
struct IssueCredentialPublicInputs {
    issuer: ShieldedAddress,
}

impl ProofInput for IssueCredential {
    type Circuit = circuit::IssueCredential;

    fn instantiate(
        &self,
        allocator: &Allocator,
    ) -> Result<circuit::IssueCredential, RelationError> {
        let private = &self.private;
        Ok(circuit::IssueCredential {
            private: circuit::IssueCredentialPrivateInputs {
                tx_context: private.tx_context.instantiate(allocator)?,
                issuer_utxo: private.issuer_utxo.instantiate(allocator)?,
                issuer_state: private.issuer_state.instantiate(allocator)?,
                user: private.user.instantiate(allocator)?,
                attribute: private.attribute.instantiate(allocator)?,
                salt: private.salt.instantiate(allocator)?,
            },
            public: circuit::IssueCredentialPublicInputs {
                issuer: self.public.issuer.instantiate(allocator)?,
            },
        })
    }
}

impl Placeholder for IssueCredential {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self {
            private: IssueCredentialPrivateInputs {
                tx_context: Placeholder::placeholder()?,
                issuer_utxo: Placeholder::placeholder()?,
                issuer_state: Placeholder::placeholder()?,
                user: Placeholder::placeholder()?,
                attribute: Placeholder::placeholder()?,
                salt: Placeholder::placeholder()?,
            },
            public: IssueCredentialPublicInputs {
                issuer: Placeholder::placeholder()?,
            },
        })
    }
}

mod circuit {
    use zk_program_sdk::{
        circuit::{
            constant, poseidon, Assert, Asset, Balance, CheckedTransaction, Circuit, CircuitVar,
            ConfidentialTransaction, DataUtxo, Owner, PublicInputs, TxContext, Utxo,
        },
        RelationError,
    };

    use crate::s35_create_issuer::circuit::{Credential, Issuer};

    pub struct IssueCredential {
        pub private: IssueCredentialPrivateInputs,
        pub public: IssueCredentialPublicInputs,
    }

    pub struct IssueCredentialPrivateInputs {
        pub tx_context: TxContext,
        pub issuer_utxo: Utxo,
        pub issuer_state: Issuer,
        pub user: Owner,
        pub attribute: CircuitVar,
        pub salt: CircuitVar,
    }

    pub struct IssueCredentialPublicInputs {
        pub issuer: Owner,
    }

    impl Circuit for IssueCredential {
        fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
            let private = &self.private;
            let issuer_hash = self.public.issuer.hash()?;
            let mut issuer = DataUtxo::new_mut(&private.issuer_utxo, &private.issuer_state)?;
            issuer
                .owner()
                .hash()?
                .assert_equal(&issuer_hash, "the issuer state has another owner")?;
            issuer
                .issuer_hash
                .assert_equal(&issuer_hash, "the issuer state is another issuer's")?;
            issuer.issued = issuer.issued.clone() + constant(1u64);
            issuer.issued.check_bits(64)?;
            let mut credential = DataUtxo::<Credential>::new_init(&private.user, &Asset::sol());
            credential.issuer_hash = issuer_hash;
            credential.attribute_commitment =
                poseidon(&[private.attribute.clone(), private.salt.clone()])?;

            ConfidentialTransaction::new(&private.tx_context, &self.public)
                .with_data_utxo(issuer)
                .with_data_utxo(credential)
                .check()
        }
    }

    impl PublicInputs for IssueCredentialPublicInputs {
        fn hash(&self, transaction_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
            poseidon(&[self.issuer.hash()?, transaction_hash.clone()])
        }
    }
}

#[test]
fn issue_credential_prove_and_verify() {
    let issuer = keypair(5);
    let address = issuer.shielded_address().expect("issuer address");
    let payer = address.solana_address().expect("payer");
    let user = keypair(6).shielded_address().expect("user address");
    let issuer_hash = address.owner_hash().expect("issuer hash");
    let issuer_state = Issuer {
        issuer_hash,
        issued: 4,
    };
    let issuer_utxo = data_input(&issuer, 0, &issuer_state, 0);
    let salt = [3u8; 32];

    let issue = IssueCredential {
        private: IssueCredentialPrivateInputs {
            tx_context: TxContext::new(),
            issuer_utxo,
            issuer_state,
            user,
            attribute: 21,
            salt,
        },
        public: IssueCredentialPublicInputs { issuer: address },
    };
    let spp_proof_inputs = issue
        .create_proof_inputs_and_encrypt(&issuer, payer, u64::MAX)
        .expect("issue credential proof inputs");
    let credential = Credential {
        issuer_hash,
        attribute_commitment: poseidon_bytes(&[right_align(&21u64.to_be_bytes()), salt]),
    };
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
        vec![
            (
                Some(address),
                Mint::SOL,
                0,
                Some(
                    borsh::to_vec(&Issuer {
                        issuer_hash,
                        issued: 5,
                    })
                    .expect("issuer bytes")
                ),
            ),
            (
                Some(user),
                Mint::SOL,
                0,
                Some(borsh::to_vec(&credential).expect("credential bytes")),
            ),
        ]
    );

    let prover =
        Groth16Prover::<IssueCredential>::new_with_test_setup().expect("issue credential setup");
    let result = prove(&prover, &issue, "issue credential proof");
    prover
        .verify(&result)
        .expect("the compressed proof verifies");
}
