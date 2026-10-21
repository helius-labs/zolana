//! Instructions of the ring authority and the upgrade authority.

use custom_ring_interface::{
    compute_unit_limit, tag, CoSignScope, CreateConfigIxData, InstructionTag, PolicyTableIxData,
    ReaderIxData, SetCoSignerIxData, SetInsertFeeIxData, SetPausedIxData, SetPolicySourceIxData,
    SourceSpec, WithdrawalThreshold,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use wincode::{config::DefaultConfig, SchemaWrite};
use zolana_client::ComputeBudgetConfig;
use zolana_interface::{pda, SYSTEM_PROGRAM_ID};
use zolana_keypair::X25519Pubkey;
use zolana_ring_client::ReaderKey;
use zolana_ring_policy::{ListId, Rule, RuleTable, SourceMap};

use crate::{submission::check_transaction_size, CoSignThreshold, CustomRing, RingError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceOwner {
    Own,
    Shared(CustomRing),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingSetup {
    pub auditor_pubkey: X25519Pubkey,
    pub has_policy: bool,
    pub anonymous: bool,
}

impl CustomRing {
    /// The upgrade authority signs and becomes the ring authority.
    pub fn create_config(
        self,
        payer: Address,
        authority: Address,
        setup: RingSetup,
    ) -> Result<Instruction, RingError> {
        let data = tagged(
            tag::CREATE_CONFIG,
            &CreateConfigIxData {
                auditor_pubkey: *setup.auditor_pubkey.as_bytes(),
                has_policy: setup.has_policy,
                anonymous: setup.anonymous,
            },
        )?;
        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(self.config_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        accounts.extend(self.upgrade_metas());
        Ok(self.ix(accounts, data))
    }

    /// The program builds SPP's registration from the config, a policy ring after its policy.
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
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
        ];
        if has_policy {
            accounts.push(AccountMeta::new_readonly(self.registry_pda(), false));
        }
        self.ix(accounts, vec![tag::INIT_SPP_RING_CONFIG])
    }

    /// The record queue is created beside the registry and its sentinel.
    pub fn create_member_registry(self, payer: Address, authority: Address) -> Instruction {
        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(self.registry_pda(), false),
            AccountMeta::new(self.queue_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        self.ix(accounts, vec![tag::CREATE_MEMBER_REGISTRY])
    }

    /// Authorizes `reader` to read the ring through the ring RPC.
    pub fn grant_read_access(
        self,
        payer: Address,
        authority: Address,
        reader: ReaderKey,
    ) -> Result<Instruction, RingError> {
        let accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(self.read_access_record_pda(&reader), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        let data = tagged(
            tag::GRANT_READ_ACCESS,
            &ReaderIxData {
                reader: reader.to_bytes(),
            },
        )?;
        Ok(self.ix(accounts, data))
    }

    pub fn revoke_read_access(
        self,
        authority: Address,
        reader: ReaderKey,
        rent_recipient: Address,
    ) -> Result<Instruction, RingError> {
        let accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(self.read_access_record_pda(&reader), false),
            AccountMeta::new(rent_recipient, false),
        ];
        let data = tagged(
            tag::REVOKE_READ_ACCESS,
            &ReaderIxData {
                reader: reader.to_bytes(),
            },
        )?;
        Ok(self.ix(accounts, data))
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
        authority: Address,
        signer: Address,
        scope: CoSignScope,
        thresholds: &[CoSignThreshold],
    ) -> Result<Instruction, RingError> {
        let body = SetCoSignerIxData {
            signer: signer.to_bytes(),
            scope: scope.bits(),
            thresholds: thresholds
                .iter()
                .map(|threshold| WithdrawalThreshold {
                    mint: threshold.mint.to_bytes(),
                    amount: threshold.amount,
                })
                .collect(),
        };
        body.check()?;
        let data = tagged(tag::SET_CO_SIGNER, &body)?;
        Ok(self.ix(self.config_write_metas(authority), data))
    }

    pub fn clear_cosigner(self, authority: Address) -> Instruction {
        self.ix(
            self.config_write_metas(authority),
            vec![tag::CLEAR_CO_SIGNER],
        )
    }

    /// [`crate::CustomRingConfig::insert_fee`], zero writes free.
    pub fn set_insert_fee(self, authority: Address, fee: u64) -> Instruction {
        let mut data = vec![tag::SET_INSERT_FEE];
        data.extend_from_slice(bytemuck::bytes_of(&SetInsertFeeIxData {
            fee: fee.to_le_bytes(),
        }));
        self.ix(self.config_write_metas(authority), data)
    }

    /// Runs under the upgrade authority, the delegate is permanent.
    pub fn set_delegate(self, authority: Address, delegate: Address) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(self.config_pda(), false),
            AccountMeta::new_readonly(self.registry_pda(), false),
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
        let mut accounts = self.policy_write_metas(authority);
        if let SourceOwner::Shared(curator) = source {
            accounts.push(AccountMeta::new_readonly(curator.registry_pda(), false));
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

    /// Pins the table and its source map, a referenced list not shared reads the ring's own registry.
    pub fn create_policy(
        self,
        authority: Address,
        rules: &RuleTable,
        shared_sources: &[(ListId, CustomRing)],
    ) -> Result<Instruction, RingError> {
        self.policy_table(
            InstructionTag::CreatePolicy,
            authority,
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
        self.policy_table(
            InstructionTag::SetPolicyRules,
            authority,
            rules,
            shared_sources,
        )
    }

    /// Curator registries follow in first-use order.
    fn policy_table(
        self,
        instruction_tag: InstructionTag,
        authority: Address,
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
        let mut entries = Vec::new();
        let sources: Vec<SourceSpec> = referenced
            .iter()
            .map(|list_id| {
                let shared = shared_sources.iter().find(|(shared, _)| *shared == list_id);
                entries.push((
                    list_id,
                    shared.map_or([0; 32], |(_, curator)| curator.registry_pda().to_bytes()),
                ));
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
        // The program stores one curator, the source map refuses a second.
        rules.encode().validate(&SourceMap::new(&entries)?)?;
        let mut accounts = self.policy_write_metas(authority);
        accounts.extend(
            curators
                .iter()
                .map(|curator| AccountMeta::new_readonly(curator.registry_pda(), false)),
        );
        let data = tagged(
            instruction_tag as u8,
            &PolicyTableIxData {
                sources,
                rules: rules.rules().iter().map(Rule::encoded).collect(),
                inline_assets: rules.inline_assets().to_vec(),
                inline_limits: rules.inline_limits().to_vec(),
                limits: rules.limits().to_vec(),
            },
        )?;
        let instruction = self.ix(accounts, data);
        check_transaction_size(
            &authority,
            &instruction,
            ComputeBudgetConfig::new(compute_unit_limit(instruction_tag)),
        )?;
        Ok(instruction)
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

    fn config_write_metas(self, authority: Address) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(self.config_pda(), false),
        ]
    }

    fn policy_write_metas(self, authority: Address) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(self.registry_pda(), false),
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
