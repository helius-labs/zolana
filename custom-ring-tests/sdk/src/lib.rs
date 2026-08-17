//! Client library for the custom ring program: instruction builders, proof-input
//! builders, and the auditor encryption codec. Instruction data, tags, and the
//! canonical public-input hashing are re-exported from the program crate so a
//! single definition serves both sides.

pub mod encryption;
pub mod instructions;
pub mod prover;
pub mod shared;

pub use custom_ring_program::{
    instructions::{
        create_config::CreateConfigIxData,
        transact::{AuditProof, CustomRingTransactIxData},
    },
    tag, CONFIG_PDA_SEED, ID as PROGRAM_ID,
};

pub use crate::{
    encryption::{
        auditor_view_tag, decrypt_tx_viewing_sk, derive_audit_shared_secret, encrypt_tx_viewing_sk,
        pack32_to_2fe, pack33_to_2fe, AuditEncryptionError, AuditorEncryption, AuditorMessage,
        AUDITOR_MESSAGE_LEN, AUDIT_ENC_INFO, DOM_SEP_CR_SHARED,
    },
    instructions::{
        create_config::CreateConfig,
        deposit::Deposit,
        init_spp_ring_config::InitSppRingConfig,
        transact::{
            to_instruction_proof, AuditProofInputError, AuditProofParams, PendingAuditProof,
            RingTransactWithAudit,
        },
    },
    prover::CustomRingProverClient,
    shared::{config_pda, ring_auth_pda},
};
