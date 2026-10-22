//! Instructions of the ring authority and the upgrade authority.

use custom_ring_interface::{
    compute_unit_limit, tag, CoSignScope, CreateConfigIxData, InstructionTag, PolicyTableIxData,
    ReaderIxData, RingKind, SetCoSignerIxData, SetInsertFeeIxData, SetPausedIxData,
    SetPolicySourceIxData, SourceSpec, WithdrawalThreshold,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use wincode::{config::DefaultConfig, SchemaWrite};
use zolana_client::ComputeBudgetConfig;
use zolana_interface::{pda, SYSTEM_PROGRAM_ID};
use zolana_keypair::X25519Pubkey;
use zolana_ring_client::ReaderKey;
use zolana_ring_policy::{ListId, Rule, RuleTable, SourceMap};

use crate::{
    submission::check_transaction_size, CoSignThreshold, CustomRing, CustomRingConfig, RingError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceOwner {
    Own,
    Shared(CustomRing),
}

/// The upgrade authority signs and becomes the ring authority.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateConfig {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub auditor_pubkey: X25519Pubkey,
    pub kind: RingKind,
}

/// The program builds SPP's registration from the config, a policy ring after its policy.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct InitSppRingConfig<'a> {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub config: &'a CustomRingConfig,
}

/// The record queue is created beside the registry and its sentinel.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateMemberRegistry {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
}

/// Authorizes `reader` to read the ring through the ring RPC.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantReader {
    pub ring: CustomRing,
    pub payer: Address,
    pub authority: Address,
    pub reader: ReaderKey,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevokeReader {
    pub ring: CustomRing,
    pub authority: Address,
    pub reader: ReaderKey,
    pub rent_recipient: Address,
}

/// Both keys sign, a mistyped address cannot strand the config.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetAuthority {
    pub ring: CustomRing,
    pub authority: Address,
    pub new_authority: Address,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetCoSigner<'a> {
    pub ring: CustomRing,
    pub authority: Address,
    pub signer: Address,
    pub scope: CoSignScope,
    pub thresholds: &'a [CoSignThreshold],
}

/// Runs under the upgrade authority, the delegate signs and stays for good.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetDelegate {
    pub ring: CustomRing,
    pub authority: Address,
    pub delegate: Address,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetSourceOwner {
    pub ring: CustomRing,
    pub authority: Address,
    pub list_id: ListId,
    pub source: SourceOwner,
}

/// A referenced list not shared reads the ring's own registry.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct PolicyRules<'a> {
    pub ring: CustomRing,
    pub authority: Address,
    pub rules: &'a RuleTable,
    pub shared_sources: &'a [(ListId, CustomRing)],
}

impl CreateConfig {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let data = tagged(
            tag::CREATE_CONFIG,
            &CreateConfigIxData {
                auditor_pubkey: *self.auditor_pubkey.as_bytes(),
                kind: self.kind,
            },
        )?;
        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(self.ring.config_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        accounts.extend(self.ring.upgrade_metas());
        Ok(self.ring.ix(accounts, data))
    }
}

impl InitSppRingConfig<'_> {
    pub fn instruction(self) -> Instruction {
        let ring = self.ring;
        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new_readonly(pda::protocol_config(), false),
            AccountMeta::new(ring.ring_auth_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
        ];
        if self.config.has_policy {
            accounts.push(AccountMeta::new_readonly(ring.registry_pda(), false));
        }
        ring.ix(accounts, vec![tag::INIT_SPP_RING_CONFIG])
    }
}

impl CreateMemberRegistry {
    pub fn instruction(self) -> Instruction {
        let ring = self.ring;
        let accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new(ring.registry_pda(), false),
            AccountMeta::new(ring.queue_pda(), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        ring.ix(accounts, vec![tag::CREATE_MEMBER_REGISTRY])
    }
}

impl GrantReader {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let ring = self.ring;
        let accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new(ring.read_access_record_pda(&self.reader), false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ];
        Ok(ring.ix(accounts, reader_data(tag::GRANT_READ_ACCESS, self.reader)?))
    }
}

impl RevokeReader {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let ring = self.ring;
        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(ring.config_pda(), false),
            AccountMeta::new(ring.read_access_record_pda(&self.reader), false),
            AccountMeta::new(self.rent_recipient, false),
        ];
        Ok(ring.ix(accounts, reader_data(tag::REVOKE_READ_ACCESS, self.reader)?))
    }
}

impl SetAuthority {
    pub fn instruction(self) -> Instruction {
        let accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(self.new_authority, true),
            AccountMeta::new(self.ring.config_pda(), false),
        ];
        self.ring.ix(accounts, vec![tag::SET_AUTHORITY])
    }
}

impl SetCoSigner<'_> {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let body = SetCoSignerIxData {
            signer: self.signer.to_bytes(),
            scope: self.scope.bits(),
            thresholds: self
                .thresholds
                .iter()
                .map(|threshold| WithdrawalThreshold {
                    mint: threshold.mint.to_bytes(),
                    amount: threshold.amount,
                })
                .collect(),
        };
        body.check()?;
        let data = tagged(tag::SET_CO_SIGNER, &body)?;
        Ok(self
            .ring
            .ix(self.ring.config_write_metas(self.authority), data))
    }
}

impl SetDelegate {
    pub fn instruction(self) -> Instruction {
        let ring = self.ring;
        let mut accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(ring.config_pda(), false),
            AccountMeta::new_readonly(self.delegate, true),
            AccountMeta::new_readonly(ring.registry_pda(), false),
        ];
        accounts.extend(ring.upgrade_metas());
        ring.ix(accounts, vec![tag::SET_DELEGATE])
    }
}

impl SetSourceOwner {
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let ring = self.ring;
        let mut accounts = ring.policy_write_metas(self.authority);
        if let SourceOwner::Shared(curator) = self.source {
            accounts.push(AccountMeta::new_readonly(curator.registry_pda(), false));
        }
        let data = tagged(
            tag::SET_POLICY_SOURCE,
            &SetPolicySourceIxData {
                list_id: self.list_id as u8,
                source: u8::from(matches!(self.source, SourceOwner::Shared(_))),
            },
        )?;
        Ok(ring.ix(accounts, data))
    }
}

impl PolicyRules<'_> {
    /// Pins the table and its source map.
    pub fn create(self) -> Result<Instruction, RingError> {
        self.table(InstructionTag::CreatePolicy)
    }

    /// Replaces the pinned table and the complete source map.
    pub fn replace(self) -> Result<Instruction, RingError> {
        self.table(InstructionTag::SetPolicyRules)
    }

    /// Curator registries follow in first-use order.
    fn table(self, instruction_tag: InstructionTag) -> Result<Instruction, RingError> {
        let Self {
            ring,
            authority,
            rules,
            shared_sources,
        } = self;
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
        let mut accounts = ring.policy_write_metas(authority);
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
        let instruction = ring.ix(accounts, data);
        check_transaction_size(
            &authority,
            &instruction,
            ComputeBudgetConfig::new(compute_unit_limit(instruction_tag)),
        )?;
        Ok(instruction)
    }
}

impl CustomRing {
    pub fn pause(self, authority: Address) -> Result<Instruction, RingError> {
        self.set_paused(authority, SetPausedIxData { paused: true })
    }

    pub fn resume(self, authority: Address) -> Result<Instruction, RingError> {
        self.set_paused(authority, SetPausedIxData { paused: false })
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

    fn set_paused(
        self,
        authority: Address,
        state: SetPausedIxData,
    ) -> Result<Instruction, RingError> {
        let accounts = vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(self.config_pda(), false),
            AccountMeta::new(self.ring_auth_pda(), false),
            AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
        ];
        Ok(self.ix(accounts, tagged(tag::SET_PAUSED, &state)?))
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

fn reader_data(instruction_tag: u8, reader: ReaderKey) -> Result<Vec<u8>, RingError> {
    tagged(
        instruction_tag,
        &ReaderIxData {
            reader: reader.to_bytes(),
        },
    )
}

pub(crate) fn tagged<T: SchemaWrite<DefaultConfig, Src = T>>(
    instruction_tag: u8,
    body: &T,
) -> Result<Vec<u8>, RingError> {
    let mut data = vec![instruction_tag];
    data.extend(wincode::serialize(body)?);
    Ok(data)
}
