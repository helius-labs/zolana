//! Client library for the custom ring program: instruction builders, proof-input
//! builders, and the auditor encryption codec. Instruction data, tags, and the
//! canonical public-input hashing are defined in `custom-ring-interface` so a single
//! definition serves both sides.

mod instructions;
mod lookup_table;
mod shared;
mod transfer;
#[cfg(feature = "solana-rpc")]
mod v0;

pub use custom_ring_interface::{
    tag, CreateConfigIxData, CustomRingProof, CustomRingTransactIxData, ReaderIxData,
    CONFIG_PDA_SEED, CREATE_CONFIG_COMPUTE_UNIT_LIMIT, INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
    READ_ACCESS_COMPUTE_UNIT_LIMIT, READ_ACCESS_RECORD_PDA_SEED, SET_AUTHORITY_COMPUTE_UNIT_LIMIT,
};

pub use zolana_interface::instruction::{DepositAsset, DepositSplAccounts};
pub use zolana_ring_client::{
    auditor_view_tag, AuditEncryptionError, AuditorEncryption, AuditorMessage, AUDITOR_MESSAGE_LEN,
};

pub use crate::{
    instructions::{
        create_config::{CreateConfig, CreateConfigError},
        deposit::Deposit,
        grant_read_access::GrantReadAccess,
        init_spp_ring_config::InitSppRingConfig,
        revoke_read_access::RevokeReadAccess,
        set_authority::SetAuthority,
        transact::{
            to_instruction_proof, CustomRingPrivateTxHash, CustomRingProofError,
            CustomRingProofInputError, CustomRingProofParams, CustomRingProofRequest,
            CustomRingPublicInputHash, CustomRingTransact, EncryptedAudit, PendingCustomRingProof,
        },
    },
    shared::{AccountReadError, CustomRing, CustomRingConfig, ReaderKey, ReaderKeyError},
    transfer::{
        AsyncTransferProofEnvironment, CustomRingTransfer, CustomRingTransferInput, DepositError,
        ProvenTransfer, RingDeposit, RingDepositReceipt, TransferError, TransferProofEnvironment,
    },
};

/// Every account a custom-ring transact must place in a lookup table. A key left
/// out costs 32 message bytes the transact cannot spare, so a host assembling
/// the v0 message itself needs the same list [`V0WithLookupTable`] builds.
pub use crate::lookup_table::{lookup_table_addresses, TRANSACT_COMPUTE_UNIT_LIMIT};
#[cfg(feature = "solana-rpc")]
pub use crate::v0::{SendV0Error, V0WithLookupTable};
