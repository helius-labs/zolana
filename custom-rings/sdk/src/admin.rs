//! Instructions of the ring authority and the upgrade authority.

use core::num::NonZeroU64;

use custom_ring_interface::{
    compute_unit_limit, tag, CoSignScope, CreateConfigIxData, CustomRingError, InstructionTag,
    PolicyTableIxData, ReaderIxData, SetCoSignerIxData, SetDepositAuditIxData, SetPausedIxData,
    SetPolicySourceIxData, SetSpendWindowIxData, SourceSpec, WithdrawalThreshold,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1::MAX_TRANSACTION_SIZE;
use wincode::{config::DefaultConfig, SchemaWrite};
use zolana_client::{transaction_size, ComputeBudgetConfig};
use zolana_interface::{is_reserved_p256_derivation_point, pda};
use zolana_keypair::P256Pubkey;
use zolana_ring_client::ReaderKey;
use zolana_ring_policy::{ListId, Rule, RuleTable};

use crate::{CoSignThreshold, CustomRing, RingError};

/// The system program is the all-zero address.
const SYSTEM: Address = Address::new_from_array([0; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceOwner {
    Own,
    Shared(CustomRing),
}

#[must_use]
pub struct SetSpendWindow {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    /// SOL under the zero address.
    pub mint: Address,
    /// Nonzero, windows start at multiples of it.
    pub window_slots: u64,
    /// Zero leaves the direction uncapped, at least one cap is nonzero.
    pub deposit_cap: u64,
    pub withdrawal_cap: u64,
}

impl SetSpendWindow {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let pda = self.ring.spend_window_pda(&self.mint);
        let (deposit_cap, withdrawal_cap) = (
            NonZeroU64::new(self.deposit_cap),
            NonZeroU64::new(self.withdrawal_cap),
        );
        if deposit_cap.is_none() && withdrawal_cap.is_none() {
            return Err(CustomRingError::UncappedSpendWindow.into());
        }
        let data = tagged(
            tag::SET_SPEND_WINDOW,
            &SetSpendWindowIxData {
                mint: self.mint.to_bytes(),
                window_slots: self.window_slots,
                deposit_cap,
                withdrawal_cap,
            },
        )?;
        Ok(self.ring.ix(
            self.ring.upsert_metas(self.payer, self.authority, pda),
            data,
        ))
    }
}

impl CustomRing {
    /// The authority signs, so the recorded authority consented to the role.
    pub fn create_config(
        self,
        payer: Address,
        authority: Address,
        auditor_pubkey: P256Pubkey,
        has_policy: bool,
    ) -> Result<Instruction, RingError> {
        if is_reserved_p256_derivation_point(auditor_pubkey.as_bytes()) {
            return Err(RingError::ReservedAuditorKey);
        }
        let data = tagged(
            tag::CREATE_CONFIG,
            &CreateConfigIxData {
                auditor_pubkey: *auditor_pubkey.as_bytes(),
                has_policy,
            },
        )?;
        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(self.config_pda(), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ];
        accounts.extend(self.upgrade_metas());
        Ok(self.ix(accounts, data))
    }

    /// The program builds the SPP registration from the config, a client cannot steer it.
    pub fn init_spp_ring_config(
        self,
        payer: Address,
        authority: Address,
        has_policy: bool,
    ) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(self.ring_auth_pda(), false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
        ];
        if has_policy {
            accounts.push(AccountMeta::new_readonly(self.policy_config_pda(), false));
        }
        self.ix(accounts, vec![tag::INIT_SPP_RING_CONFIG])
    }

    pub fn create_key_registry_root(self, payer: Address, authority: Address) -> Instruction {
        let metas = self.upsert_metas(payer, authority, self.key_registry_root_pda());
        self.ix(metas, vec![tag::CREATE_KEY_REGISTRY_ROOT])
    }

    /// Authorizes `reader` to read the ring through the ring RPC.
    pub fn grant_read_access(
        self,
        payer: Address,
        authority: Address,
        reader: ReaderKey,
    ) -> Result<Instruction, RingError> {
        let metas = self.upsert_metas(payer, authority, self.read_access_record_pda(&reader));
        let data = tagged(
            tag::GRANT_READ_ACCESS,
            &ReaderIxData {
                reader: reader.to_bytes(),
            },
        )?;
        Ok(self.ix(metas, data))
    }

    pub fn revoke_read_access(
        self,
        authority: Address,
        reader: ReaderKey,
        rent_recipient: Address,
    ) -> Result<Instruction, RingError> {
        let metas = self.close_metas(
            authority,
            self.read_access_record_pda(&reader),
            rent_recipient,
        );
        let data = tagged(
            tag::REVOKE_READ_ACCESS,
            &ReaderIxData {
                reader: reader.to_bytes(),
            },
        )?;
        Ok(self.ix(metas, data))
    }

    /// Both keys sign, a mistyped address cannot strand the config.
    pub fn set_authority(self, authority: Address, new_authority: Address) -> Instruction {
        let accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(new_authority, true),
            AccountMeta::new(self.config_pda(), false),
        ];
        self.ix(accounts, vec![tag::SET_AUTHORITY])
    }

    pub fn set_paused(self, authority: Address, paused: bool) -> Result<Instruction, RingError> {
        let data = tagged(tag::SET_PAUSED, &SetPausedIxData { paused })?;
        let accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(self.ring_auth_pda(), false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
        ];
        Ok(self.ix(accounts, data))
    }

    pub fn set_cosigner(
        self,
        payer: Address,
        authority: Address,
        signer: Address,
        scope: CoSignScope,
        thresholds: &[CoSignThreshold],
    ) -> Result<Instruction, RingError> {
        let data = tagged(
            tag::SET_CO_SIGNER,
            &SetCoSignerIxData {
                signer: signer.to_bytes(),
                scope: scope.bits(),
                thresholds: thresholds
                    .iter()
                    .map(|threshold| WithdrawalThreshold {
                        mint: threshold.mint.to_bytes(),
                        amount: threshold.amount,
                    })
                    .collect(),
            },
        )?;
        Ok(self.ix(
            self.upsert_metas(payer, authority, self.cosigner_pda()),
            data,
        ))
    }

    pub fn clear_cosigner(self, authority: Address, rent_recipient: Address) -> Instruction {
        let metas = self.close_metas(authority, self.cosigner_pda(), rent_recipient);
        self.ix(metas, vec![tag::CLEAR_CO_SIGNER])
    }

    pub fn clear_spend_window(
        self,
        authority: Address,
        mint: Address,
        rent_recipient: Address,
    ) -> Instruction {
        let metas = self.close_metas(authority, self.spend_window_pda(&mint), rent_recipient);
        let mut data = vec![tag::CLEAR_SPEND_WINDOW];
        data.extend_from_slice(mint.as_array());
        self.ix(metas, data)
    }

    pub fn set_deposit_audit(
        self,
        payer: Address,
        authority: Address,
        required: bool,
    ) -> Result<Instruction, RingError> {
        let data = tagged(tag::SET_DEPOSIT_AUDIT, &SetDepositAuditIxData { required })?;
        Ok(self.ix(
            self.upsert_metas(payer, authority, self.deposit_audit_pda()),
            data,
        ))
    }

    /// Runs under the upgrade authority, the delegate is permanent.
    pub fn set_delegate(
        self,
        payer: Address,
        authority: Address,
        delegate: Address,
    ) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(self.config_pda(), false),
            AccountMeta::new(self.delegate_pda(), false),
            AccountMeta::new_readonly(self.key_registry_root_pda(), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ];
        accounts.extend(self.upgrade_metas());
        let mut data = vec![tag::SET_DELEGATE];
        data.extend_from_slice(delegate.as_array());
        self.ix(accounts, data)
    }

    pub fn set_source_owner(
        self,
        authority: Address,
        list_id: ListId,
        source: SourceOwner,
    ) -> Result<Instruction, RingError> {
        let mut accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(self.policy_config_pda(), false),
        ];
        if let SourceOwner::Shared(curator) = source {
            accounts.push(AccountMeta::new_readonly(
                curator.policy_config_pda(),
                false,
            ));
        }
        let data = tagged(
            tag::SET_POLICY_SOURCE,
            &SetPolicySourceIxData {
                list_id: list_id as u8,
                source: u8::from(matches!(source, SourceOwner::Shared(_))),
            },
        )?;
        Ok(self.ix(accounts, data))
    }

    /// Pins the table and its source map, a referenced list not shared reads the ring's own entries.
    pub fn create_policy(
        self,
        payer: Address,
        authority: Address,
        address_tree: Address,
        rules: &RuleTable,
        shared_sources: &[(ListId, CustomRing)],
    ) -> Result<Instruction, RingError> {
        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(self.policy_config_pda(), false),
            AccountMeta::new_readonly(address_tree, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ];
        accounts.extend(self.upgrade_metas());
        self.policy_table(
            InstructionTag::CreatePolicy,
            payer,
            accounts,
            rules,
            shared_sources,
        )
    }

    /// Replaces the pinned table and the complete source map.
    pub fn set_policy_rules(
        self,
        authority: Address,
        rules: &RuleTable,
        shared_sources: &[(ListId, CustomRing)],
    ) -> Result<Instruction, RingError> {
        let mut accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(self.policy_config_pda(), false),
        ];
        accounts.extend(self.upgrade_metas());
        let instruction = InstructionTag::SetPolicyRules;
        self.policy_table(instruction, authority, accounts, rules, shared_sources)
    }

    /// Curator policy configs follow in first-use order, the transaction must fit v1.
    fn policy_table(
        self,
        instruction: InstructionTag,
        payer: Address,
        mut accounts: Vec<AccountMeta>,
        rules: &RuleTable,
        shared_sources: &[(ListId, CustomRing)],
    ) -> Result<Instruction, RingError> {
        let referenced = rules.referenced();
        if let Some((list_id, _)) = shared_sources
            .iter()
            .find(|(list_id, _)| !referenced.contains(*list_id))
        {
            return Err(RingError::UnreferencedList(*list_id));
        }
        let mut curators: Vec<CustomRing> = Vec::new();
        let sources = referenced
            .iter()
            .map(|list_id| {
                let shared = shared_sources.iter().find(|(shared, _)| *shared == list_id);
                let source = shared.map_or(0, |&(_, curator)| {
                    let index = curators.iter().position(|known| *known == curator);
                    1 + index.unwrap_or_else(|| {
                        curators.push(curator);
                        curators.len() - 1
                    }) as u8
                });
                SourceSpec {
                    list_id: list_id as u8,
                    source,
                }
            })
            .collect();
        accounts.extend(
            curators
                .iter()
                .map(|curator| AccountMeta::new_readonly(curator.policy_config_pda(), false)),
        );
        let data = tagged(
            instruction as u8,
            &PolicyTableIxData {
                sources,
                rules: rules.rules().iter().map(Rule::encoded).collect(),
                inline_assets: rules.inline_assets().to_vec(),
                inline_limits: rules.inline_limits().to_vec(),
                window_slots: rules.window_slots(),
                velocity: rules.velocity().to_vec(),
            },
        )?;
        let ix = self.ix(accounts, data);
        let budget = ComputeBudgetConfig::new(compute_unit_limit(instruction));
        fit(payer, budget, ix)
    }

    fn ix(self, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
        Instruction {
            program_id: self.program_id(),
            accounts,
            data,
        }
    }

    fn upgrade_metas(self) -> [AccountMeta; 2] {
        [
            AccountMeta::new_readonly(self.program_id(), false),
            AccountMeta::new_readonly(self.program_data_pda(), false),
        ]
    }

    fn upsert_metas(self, payer: Address, authority: Address, pda: Address) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(pda, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ]
    }

    fn close_metas(
        self,
        authority: Address,
        pda: Address,
        rent_recipient: Address,
    ) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(pda, false),
            AccountMeta::new(rent_recipient, false),
        ]
    }
}

pub(crate) fn tagged<T: SchemaWrite<DefaultConfig, Src = T>>(
    instruction_tag: u8,
    body: &T,
) -> Result<Vec<u8>, RingError> {
    let mut data = vec![instruction_tag];
    data.extend(wincode::serialize(body)?);
    Ok(data)
}

/// The signed transaction must fit v1, its address cap cannot bind a policy table.
pub(crate) fn fit(
    payer: Address,
    budget: ComputeBudgetConfig,
    instruction: Instruction,
) -> Result<Instruction, RingError> {
    let size = transaction_size(&payer, core::slice::from_ref(&instruction), budget)?;
    if size.bytes > MAX_TRANSACTION_SIZE {
        return Err(RingError::TransactionTooLarge {
            bytes: size.bytes,
            limit: MAX_TRANSACTION_SIZE,
        });
    }
    Ok(instruction)
}
