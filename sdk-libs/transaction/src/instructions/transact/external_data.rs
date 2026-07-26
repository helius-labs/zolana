use solana_address::Address;
use zolana_event::MessageData;
use zolana_interface::instruction::{
    instruction_data::transact::{
        ExternalDataHash, PublicLeg, ResolvedOutput, ResolvedPublicLeg, TransactOutput,
    },
    tag,
};
use zolana_interface::pda;
use zolana_interface::MAX_WIRE_PUBLIC_LEGS;

use crate::{error::TransactionError, SOL_MINT};

/// One ordered public settlement leg, including the accounts committed by the
/// canonical external-data hash. SPL legs retain their mint so proof public
/// movements can be derived without inspecting private inputs or outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementLeg {
    Sol {
        is_deposit: bool,
        amount: u64,
        user_sol_account: Address,
    },
    Spl {
        mint: Address,
        is_deposit: bool,
        amount: u64,
        user_spl_token: Address,
        spl_token_interface: Address,
    },
}

impl SettlementLeg {
    pub const fn amount(self) -> u64 {
        match self {
            Self::Sol { amount, .. } | Self::Spl { amount, .. } => amount,
        }
    }

    pub const fn is_deposit(self) -> bool {
        match self {
            Self::Sol { is_deposit, .. } | Self::Spl { is_deposit, .. } => is_deposit,
        }
    }

    pub const fn asset(self) -> Address {
        match self {
            Self::Sol { .. } => SOL_MINT,
            Self::Spl { mint, .. } => mint,
        }
    }

    pub fn public_leg(self) -> PublicLeg {
        match self {
            Self::Sol {
                is_deposit, amount, ..
            } => PublicLeg::Sol { is_deposit, amount },
            Self::Spl {
                mint,
                is_deposit,
                amount,
                ..
            } => PublicLeg::Spl {
                is_deposit,
                amount,
                vault_bump: pda::spl_asset_vault_bump(mint.as_array()),
            },
        }
    }

    fn resolved(self) -> ResolvedPublicLeg {
        match self {
            Self::Sol {
                is_deposit,
                amount,
                user_sol_account,
            } => ResolvedPublicLeg::Sol {
                is_deposit,
                amount,
                recipient: *user_sol_account.as_array(),
            },
            Self::Spl {
                is_deposit,
                amount,
                user_spl_token,
                spl_token_interface,
                ..
            } => ResolvedPublicLeg::Spl {
                is_deposit,
                amount,
                user_token_account: *user_spl_token.as_array(),
                vault: *spl_token_interface.as_array(),
            },
        }
    }
}

/// Transaction-level public data the proofs commit to via `external_data_hash`.
/// The hash is computed by the canonical [`ExternalDataHash`] from the interface
/// crate, so the client and the Solana program agree byte-for-byte. Each output
/// carries its commitment, wire `owner_tag`, and optional ciphertext; the
/// resolved 32-byte owner tags are paired at construction so [`Self::hash`]
/// needs no transaction context and cannot drift from the wire tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalData {
    pub instruction_discriminator: u8,
    pub expiry_unix_ts: u64,
    pub public_legs: Vec<SettlementLeg>,
    /// Optional transaction-level UTXO- and zone-specific external data
    /// digests folded into `external_data_hash`; `None` for a default-zone
    /// `transact`.
    pub data_hash: Option<[u8; 32]>,
    pub zone_data_hash: Option<[u8; 32]>,
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; 16],
    /// All `M` outputs in tree-append order (SPL change, SOL change, recipients
    /// / dummies). A `None` `data` marks a slot covered by a preceding bundle.
    pub outputs: Vec<TransactOutput>,
    /// The resolved 32-byte owner tag of each output, paired 1:1 with `outputs`
    /// at construction. `hash()` covers these resolved bytes rather than the
    /// wire `OwnerTag`, matching the program's OWNER public input.
    pub resolved_owner_tags: Vec<[u8; 32]>,
    /// Ciphertexts bound to no output commitment; empty for all current flows.
    pub messages: Vec<MessageData>,
}

impl ExternalData {
    pub fn new(
        tx_viewing_pk: [u8; 33],
        salt: [u8; 16],
        outputs: Vec<TransactOutput>,
        resolved_owner_tags: Vec<[u8; 32]>,
        messages: Vec<MessageData>,
    ) -> Self {
        Self {
            instruction_discriminator: tag::TRANSACT,
            expiry_unix_ts: u64::MAX, // default no expiry, not necessary for confidential transfers
            public_legs: Vec::new(),
            data_hash: None,
            zone_data_hash: None,
            tx_viewing_pk,
            salt,
            outputs,
            resolved_owner_tags,
            messages,
        }
    }

    pub fn with_public_leg(mut self, leg: SettlementLeg) -> Result<Self, TransactionError> {
        validate_settlement_legs(&self.public_legs)?;
        validate_settlement_leg(leg)?;
        let len =
            self.public_legs
                .len()
                .checked_add(1)
                .ok_or(TransactionError::TooManyPublicLegs {
                    got: usize::MAX,
                    max: MAX_WIRE_PUBLIC_LEGS,
                })?;
        if len > MAX_WIRE_PUBLIC_LEGS {
            return Err(TransactionError::TooManyPublicLegs {
                got: len,
                max: MAX_WIRE_PUBLIC_LEGS,
            });
        }
        self.public_legs.push(leg);
        Ok(self)
    }

    pub fn with_public_legs(
        mut self,
        public_legs: Vec<SettlementLeg>,
    ) -> Result<Self, TransactionError> {
        validate_settlement_legs(&public_legs)?;
        self.public_legs = public_legs;
        Ok(self)
    }

    pub fn with_zone_hashes(
        mut self,
        data_hash: [u8; 32],
        zone_data_hash: [u8; 32],
    ) -> Result<Self, TransactionError> {
        if self.data_hash.is_some() || self.zone_data_hash.is_some() {
            return Err(TransactionError::ZoneHashesAlreadySet);
        }
        self.data_hash = Some(data_hash);
        self.zone_data_hash = Some(zone_data_hash);
        Ok(self)
    }

    /// `external_data_hash` via the canonical interface [`ExternalDataHash`].
    /// Builds [`ResolvedOutput`]s from the outputs paired with their resolved
    /// owner tags, so the client and program hash the identical preimage.
    pub fn hash(&self) -> Result<[u8; 32], TransactionError> {
        validate_settlement_legs(&self.public_legs)?;
        if self.outputs.len() != self.resolved_owner_tags.len() {
            return Err(TransactionError::Hash(
                "resolved owner tags do not pair 1:1 with outputs".to_string(),
            ));
        }
        let resolved: Vec<ResolvedOutput> = self
            .outputs
            .iter()
            .zip(self.resolved_owner_tags.iter())
            .map(|(output, owner_tag)| ResolvedOutput {
                utxo_hash: &output.utxo_hash,
                owner_tag: *owner_tag,
                data: output.data.as_deref(),
            })
            .collect();
        let public_legs: Vec<_> = self
            .public_legs
            .iter()
            .copied()
            .map(SettlementLeg::resolved)
            .collect();
        ExternalDataHash {
            spp_instruction_discriminator: self.instruction_discriminator,
            expiry_unix_ts: self.expiry_unix_ts,
            public_legs: &public_legs,
            data_hash: self.data_hash,
            zone_data_hash: self.zone_data_hash,
            outputs: &resolved,
            messages: &self.messages,
        }
        .hash()
        .map_err(|e| TransactionError::Hash(format!("{e:?}")))
    }
}

fn validate_settlement_legs(legs: &[SettlementLeg]) -> Result<(), TransactionError> {
    if legs.len() > MAX_WIRE_PUBLIC_LEGS {
        return Err(TransactionError::TooManyPublicLegs {
            got: legs.len(),
            max: MAX_WIRE_PUBLIC_LEGS,
        });
    }
    for leg in legs {
        validate_settlement_leg(*leg)?;
    }
    Ok(())
}

fn validate_settlement_leg(leg: SettlementLeg) -> Result<(), TransactionError> {
    if leg.amount() == 0 {
        return Err(TransactionError::ZeroPublicLegAmount);
    }
    if matches!(leg, SettlementLeg::Spl { mint, .. } if mint == SOL_MINT) {
        return Err(TransactionError::SettlementTargetMismatch { asset: SOL_MINT });
    }
    Ok(())
}
