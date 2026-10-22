//! `deploy`, the Solana CLI writes the buffer, every other loader call is ours.

use std::{
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_interface::{MemberRegistry, RingAccount, RingProgramConfig, VIEWING_PUBKEY_TAG};
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_loader_v3_interface::{instruction::extend_program, state::UpgradeableLoaderState};
use solana_sbpf::elf_parser::{
    consts::{ELFOSABI_NONE, EM_BPF, EM_SBPF, ET_DYN, PF_X, PT_LOAD},
    Elf64,
};
use solana_signer::Signer;
use zolana_client::{ProgramData, Rpc};

use crate::{
    config::expand_tilde, file, line, policy::Pinned, release::RingProgram, tool::SOLANA,
    workspace::Workspace, Context, DeployArgs, Target,
};

/// The smallest growth of `ProgramData` the loader accepts.
const MIN_EXTEND_BYTES: usize = 10_240;
/// A deploy is hundreds of writes plus the loader calls.
const DEPLOY_FEE_BUDGET: u64 = 20_000_000;
const USABLE_TIMEOUT: Duration = Duration::from_secs(60);
const SLOT_POLL: Duration = Duration::from_millis(400);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProgramBinary {
    pub len: usize,
    pub sha256: [u8; 32],
}

pub fn run(ctx: &mut Context, args: DeployArgs) -> Result<()> {
    let workspace = Workspace::from_env()?;
    ensure!(
        workspace.is_none() || ctx.config.target == Target::Localnet,
        "workspace artifacts are only supported on localnet"
    );
    let program_so = match (args.program_so, workspace) {
        (Some(path), _) => ctx.path(&path),
        (None, Some(workspace)) => workspace.ring_program_so()?,
        (None, None) => {
            let program = RingProgram::from_lock()?;
            let release = format!("{} {}", program.tag, program.asset.name);
            line("release", release);
            program.ensure()?
        }
    };
    line("binary", program_so.display());
    let authority = ctx.config.upgrade_authority()?;
    let program_keypair = ctx.path(&args.program_keypair);
    let outcome = upload(ctx, &authority, &program_keypair, &program_so)?;
    let program = ctx.ring.program_id();
    println!("{outcome} {program} under {}", authority.pubkey());
    Ok(())
}

/// The first deploy reads the program keypair, an upgrade checks the configs it keeps.
fn upload(
    ctx: &Context,
    authority: &Keypair,
    program_keypair: &Path,
    program_so: &Path,
) -> Result<&'static str> {
    let binary = ProgramBinary::read(program_so)?;
    let program = ctx.ring.program_id();
    let deployed = program_data(ctx)?;
    match &deployed {
        Some(data) => {
            check_upgrade_authority(program, data, authority.pubkey())?;
            if binary.deployed_sha256(ctx)? == Some(binary.sha256) {
                return Ok("present");
            }
            let ring_config = ctx.rpc().get_account(ctx.ring.config_pda())?;
            ensure_ring_config_compatible(program, ring_config.as_ref())?;
            let registry = ctx.rpc().get_account(ctx.ring.registry_pda())?;
            ensure_registry_compatible(program, registry.as_ref())?;
        }
        None => {
            let found = file::read_keypair(program_keypair)
                .context("the first deploy needs the program keypair")?
                .pubkey();
            ensure!(
                found == program,
                "program keypair is {found}, ring.toml names {program}"
            );
        }
    }
    // A short balance fails before the loader writes.
    let required = required_balance(ctx.rpc(), binary.len, deployed.as_ref())?;
    ctx.fund(authority.pubkey(), required)?;
    if let Some(data) = deployed.filter(|data| binary.len > data.capacity) {
        let bytes = (binary.len - data.capacity).max(MIN_EXTEND_BYTES);
        println!("extending program data by {bytes} bytes");
        let extend = extend_program(&program, Some(&authority.pubkey()), u32::try_from(bytes)?);
        ctx.send(&[authority], &[extend])?;
    }
    let authority_keypair = expand_tilde(ctx.config.upgrade_authority_keypair())?;
    let mut command = Command::new("solana");
    // RPC only, the TPU client wants a websocket port another service may hold.
    command
        .args(["program", "deploy", "--use-rpc", "--url"])
        .arg(&ctx.config.urls().rpc)
        .arg("--keypair")
        .arg(&authority_keypair)
        .arg("--upgrade-authority")
        .arg(&authority_keypair)
        .arg("--program-id");
    match deployed {
        Some(_) => command.arg(program.to_string()),
        None => command.arg(program_keypair),
    };
    SOLANA
        .named("solana program deploy")
        .run(command.arg(program_so))?;
    ctx.rpc()
        .assert_executable(&program)
        .with_context(|| format!("program {program} is not executable after deploy"))?;
    binary.verify_deployed(ctx)?;
    let slot = program_data(ctx)?
        .with_context(|| not_program_data(ctx))?
        .slot;
    wait_until_usable(ctx.rpc(), program, slot)?;
    Ok(deployed.map_or("deployed", |_| "upgraded"))
}

/// `None` when the program is not deployed under the upgradeable loader.
pub(crate) fn program_data(ctx: &Context) -> Result<Option<ProgramData>> {
    if ctx.rpc().get_account(ctx.ring.program_id())?.is_none() {
        return Ok(None);
    }
    let Some(account) = ctx.rpc().get_account(ctx.ring.program_data_pda())? else {
        return Ok(None);
    };
    let mut data = zolana_client::program_data(&account).with_context(|| not_program_data(ctx))?;
    data.upgrade_authority = data
        .upgrade_authority
        .filter(|authority| *authority != Address::default());
    Ok(Some(data))
}

/// Only the upgrade authority ring.toml names may move the program.
pub(crate) fn check_upgrade_authority(
    program: Address,
    data: &ProgramData,
    expected: Address,
) -> Result<()> {
    let Some(authority) = data.upgrade_authority else {
        bail!("program {program} is immutable, it cannot be upgraded");
    };
    ensure!(
        authority == expected,
        "program {program} is upgradeable by {authority}, ring.toml names {expected}"
    );
    Ok(())
}

fn not_program_data(ctx: &Context) -> String {
    let address = ctx.ring.program_data_pda();
    format!("{address} is not a ProgramData account")
}

impl ProgramBinary {
    pub(crate) fn read(path: &Path) -> Result<Self> {
        let bytes =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let binary = Self::parse(&bytes)?;
        zolana_cli_common::release::verify_program_keys(
            &bytes,
            custom_ring_interface::proving_key_hashes(),
        )?;
        Ok(binary)
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let elf = Elf64::parse(bytes).context("invalid SBF binary")?;
        let header = elf.file_header();
        ensure!(
            header.e_ident.ei_osabi == ELFOSABI_NONE
                && header.e_type == ET_DYN
                && matches!(header.e_machine, EM_BPF | EM_SBPF)
                && elf.program_header_table().iter().any(|segment| {
                    segment.p_type == PT_LOAD
                        && segment.p_flags & PF_X != 0
                        && segment.p_filesz != 0
                }),
            "invalid SBF binary"
        );
        Ok(Self {
            len: bytes.len(),
            sha256: Sha256::digest(bytes).into(),
        })
    }

    /// Unused loader capacity must contain only zero bytes.
    fn deployed_sha256(&self, ctx: &Context) -> Result<Option<[u8; 32]>> {
        let account = ctx.rpc().get_account(ctx.ring.program_data_pda())?;
        let account = account.with_context(|| not_program_data(ctx))?;
        Ok(deployed_bytes(&account.data, self.len).map(|deployed| Sha256::digest(deployed).into()))
    }

    pub(crate) fn verify_deployed(&self, ctx: &Context) -> Result<()> {
        let found = self.deployed_sha256(ctx)?;
        let found = found.with_context(|| not_program_data(ctx))?;
        ensure!(
            found == self.sha256,
            "program {} holds {} on chain, expected {}",
            ctx.ring.program_id(),
            hex::encode(found),
            hex::encode(self.sha256)
        );
        Ok(())
    }
}

/// An upgrade must not strand notes behind an auditor key the new program rejects.
fn ensure_ring_config_compatible(program: Address, account: Option<&Account>) -> Result<()> {
    let Some(account) = account.filter(|account| !account.data.is_empty()) else {
        return Ok(());
    };
    let config = RingProgramConfig::decode(&account.owner, &program, &account.data);
    ensure!(
        config.is_some(),
        "program {program} has an incompatible ring config, migrate its notes before deploying a fresh ring"
    );
    ensure!(
        config.is_some_and(|config| config.auditor_pubkey[0] == VIEWING_PUBKEY_TAG),
        "program {program} keeps a legacy auditor key, migrate its notes before upgrading"
    );
    Ok(())
}

/// The current schema must decode the registry and reproduce its pinned policy hash.
fn ensure_registry_compatible(program: Address, registry: Option<&Account>) -> Result<()> {
    let Some(account) = registry.filter(|account| account.owner == program) else {
        return Ok(());
    };
    ensure!(
        account.data.len() == MemberRegistry::SIZE,
        "program {program} keeps a member registry of {} bytes, the release needs {}, deploy a fresh ring",
        account.data.len(),
        MemberRegistry::SIZE
    );
    let compatible = MemberRegistry::from_data(&account.data)
        .is_some_and(|registry| Pinned::of(Box::new(*registry)).is_ok());
    ensure!(
        compatible,
        "program {program} has an incompatible member registry or policy commitment, deploy a fresh ring"
    );
    Ok(())
}

/// A first deploy pays rent for the program and its data account, an upgrade only for the
/// growth. Both pay for the write buffer, refunded when the deploy finishes.
fn required_balance<R: Rpc>(rpc: &R, so_len: usize, deployed: Option<&ProgramData>) -> Result<u64> {
    let rent = |bytes: usize| rpc.get_minimum_balance_for_rent_exemption(bytes);
    let mut lamports = DEPLOY_FEE_BUDGET + rent(UpgradeableLoaderState::size_of_buffer(so_len))?;
    match deployed {
        None => {
            lamports += rent(UpgradeableLoaderState::size_of_program())?;
            lamports += rent(UpgradeableLoaderState::size_of_programdata(so_len))?;
        }
        Some(data) if so_len > data.capacity => {
            let grown = data.capacity + (so_len - data.capacity).max(MIN_EXTEND_BYTES);
            lamports += rent(UpgradeableLoaderState::size_of_programdata(grown))?.saturating_sub(
                rent(UpgradeableLoaderState::size_of_programdata(data.capacity))?,
            );
        }
        Some(_) => {}
    }
    Ok(lamports)
}

/// The loader refuses a program in the slot it was deployed in.
fn wait_until_usable<R: Rpc>(rpc: &R, program: Address, deployed_slot: u64) -> Result<()> {
    let started = Instant::now();
    while rpc.get_slot()? <= deployed_slot {
        ensure!(
            started.elapsed() <= USABLE_TIMEOUT,
            "program {program} deployed at slot {deployed_slot} stays unusable, the validator does not advance"
        );
        thread::sleep(SLOT_POLL);
    }
    Ok(())
}

/// The loader writes the binary as given, padded to the account's capacity.
fn deployed_bytes(program_data: &[u8], so_len: usize) -> Option<&[u8]> {
    let start = UpgradeableLoaderState::size_of_programdata_metadata();
    let end = start.checked_add(so_len)?;
    if so_len == 0 || program_data.get(end..)?.iter().any(|byte| *byte != 0) {
        return None;
    }
    program_data.get(start..end)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use zolana_client::ClientError;

    use super::*;

    /// Rent as the cluster prices it, 3480 lamports per byte-year over two years.
    struct Rent;

    impl Rpc for Rent {
        fn get_minimum_balance_for_rent_exemption(
            &self,
            data_len: usize,
        ) -> Result<u64, ClientError> {
            Ok((128 + data_len as u64) * 3480 * 2)
        }
    }

    fn rent(data_len: usize) -> u64 {
        Rent.get_minimum_balance_for_rent_exemption(data_len)
            .expect("priced")
    }

    fn elf() -> Vec<u8> {
        let mut bytes = vec![0; 264];
        bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        for (offset, value) in [
            (16, ET_DYN),
            (18, EM_SBPF),
            (52, 64),
            (54, 56),
            (56, 1),
            (58, 64),
            (60, 2),
            (62, 1),
        ] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(20, 1u32), (64, PT_LOAD), (68, PF_X), (204, 3)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (32, 64u64),
            (40, 136),
            (72, 120),
            (96, 8),
            (104, 8),
            (224, 128),
            (232, 1),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn binary_validation_requires_complete_sbf_tables_and_sections() {
        let bytes = elf();
        let binary = ProgramBinary::parse(&bytes).unwrap();
        assert_eq!(binary.len, bytes.len());
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(binary.sha256, expected);
        for length in 0..bytes.len() {
            assert!(ProgramBinary::parse(&bytes[..length]).is_err());
        }
        for (offset, value) in [(18, 62u64), (40, u64::MAX), (96, u64::MAX)] {
            let mut invalid = bytes.clone();
            invalid[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(ProgramBinary::parse(&invalid).is_err());
        }
        let mut invalid = bytes;
        invalid[68..72].fill(0);
        assert!(ProgramBinary::parse(&invalid).is_err());
    }

    #[test]
    fn deployed_bytes_skip_the_metadata_and_stop_at_the_binary_length() {
        let meta = UpgradeableLoaderState::size_of_programdata_metadata();
        let mut data = vec![0u8; meta];
        data.extend_from_slice(b"elf");
        data.extend_from_slice(&[0u8; 8]);
        assert_eq!(deployed_bytes(&data, 3), Some(&b"elf"[..]));
        assert_eq!(deployed_bytes(&data, 3 + 8), Some(&data[meta..]));
        assert_eq!(deployed_bytes(&data, 3 + 9), None);
        assert_eq!(deployed_bytes(&data[..meta - 1], 0), None);
        assert_eq!(deployed_bytes(&data, 0), None);
        data[meta + 3] = 1;
        assert_eq!(deployed_bytes(&data, 3), None);
    }

    #[test]
    fn only_the_recorded_upgrade_authority_may_move_the_program() {
        let check = |upgrade_authority| {
            let data = ProgramData {
                slot: 0,
                upgrade_authority,
                capacity: 0,
            };
            check_upgrade_authority(
                Address::new_from_array([1; 32]),
                &data,
                Address::new_from_array([2; 32]),
            )
        };
        assert!(check(Some(Address::new_from_array([2; 32]))).is_ok());
        let foreign = check(Some(Address::new_from_array([3; 32]))).expect_err("foreign");
        assert!(
            foreign.to_string().contains("is upgradeable by"),
            "{foreign}"
        );
        let immutable = check(None).expect_err("immutable");
        assert!(immutable
            .to_string()
            .ends_with("is immutable, it cannot be upgraded"));
    }

    #[test]
    fn upgrades_require_a_compatible_ring_config_even_without_policy() {
        use bytemuck::Zeroable;
        let program = Address::from([7u8; 32]);
        let mut config = RingProgramConfig::zeroed();
        config.discriminator = custom_ring_interface::RING_PROGRAM_CONFIG;
        config.auditor_pubkey[0] = custom_ring_interface::VIEWING_PUBKEY_TAG;
        let account = |config: &RingProgramConfig| Account {
            owner: program,
            data: bytemuck::bytes_of(config).to_vec(),
            ..Default::default()
        };
        assert!(ensure_ring_config_compatible(program, None).is_ok());
        for mode in 0..=2 {
            config.mode = mode;
            assert!(ensure_ring_config_compatible(program, Some(&account(&config))).is_ok());
        }
        config.mode = 0;
        // An audit-only ring has no pinned policy to refuse its upgrade.
        for tag in [2, 3] {
            config.auditor_pubkey[0] = tag;
            let error =
                ensure_ring_config_compatible(program, Some(&account(&config))).unwrap_err();
            assert!(error.to_string().contains("legacy auditor key"));
        }
        config.auditor_pubkey[0] = custom_ring_interface::VIEWING_PUBKEY_TAG;
        config.mode = 3;
        assert!(ensure_ring_config_compatible(program, Some(&account(&config))).is_err());
        config.mode = 0;
        let mut retired = account(&config);
        retired.data[0] = 1;
        assert!(
            ensure_ring_config_compatible(program, Some(&retired)).is_err(),
            "a retired discriminator"
        );
        let mut wrong_owner = account(&config);
        wrong_owner.owner = Address::from([9u8; 32]);
        assert!(ensure_ring_config_compatible(program, Some(&wrong_owner)).is_err());
        let mut wrong_layout = account(&config);
        wrong_layout.data.pop();
        assert!(ensure_ring_config_compatible(program, Some(&wrong_layout)).is_err());
    }

    #[test]
    fn an_incompatible_member_registry_refuses_the_upgrade() {
        use custom_ring_interface::N_SOURCE_SLOTS;
        let program = Address::from([7u8; 32]);
        let foreign = Address::from([9u8; 32]);
        let account = |owner, data: &[u8]| Account {
            owner,
            data: data.to_vec(),
            ..Default::default()
        };
        assert!(ensure_registry_compatible(program, None).is_ok());
        let mut registry = MemberRegistry::new(0, 0);
        let audit_only = account(program, bytemuck::bytes_of(&registry));
        assert!(ensure_registry_compatible(program, Some(&audit_only)).is_ok());
        let rules = zolana_ring_policy::RuleTable::builder().build();
        registry
            .set_policy(
                [bytemuck::Zeroable::zeroed(); N_SOURCE_SLOTS],
                rules.encode(),
                0,
            )
            .unwrap();
        let pinned = account(program, bytemuck::bytes_of(&registry));
        assert!(ensure_registry_compatible(program, Some(&pinned)).is_ok());
        let short = [0; MemberRegistry::SIZE - 1];
        assert!(ensure_registry_compatible(program, Some(&account(foreign, &short))).is_ok());
        let refused = ensure_registry_compatible(program, Some(&account(program, &short)))
            .expect_err("short");
        assert!(refused.to_string().contains(&format!(
            "of {} bytes, the release needs {}",
            MemberRegistry::SIZE - 1,
            MemberRegistry::SIZE
        )));
        registry.policy_hash[0] ^= 1;
        let drifted = ensure_registry_compatible(
            program,
            Some(&account(program, bytemuck::bytes_of(&registry))),
        )
        .expect_err("drifted");
        assert!(drifted.to_string().contains("incompatible member registry"));
    }

    #[test]
    fn a_first_deploy_pays_program_data_and_buffer() {
        let so_len = 300_000;
        assert_eq!(
            required_balance(&Rent, so_len, None).expect("priced"),
            DEPLOY_FEE_BUDGET
                + rent(UpgradeableLoaderState::size_of_buffer(so_len))
                + rent(UpgradeableLoaderState::size_of_program())
                + rent(UpgradeableLoaderState::size_of_programdata(so_len))
        );
    }

    #[test]
    fn an_upgrade_pays_the_buffer_and_only_the_growth() {
        let deployed = ProgramData {
            upgrade_authority: None,
            capacity: 300_000,
            slot: 0,
        };
        let fits = required_balance(&Rent, deployed.capacity, Some(&deployed)).expect("priced");
        assert_eq!(
            fits,
            DEPLOY_FEE_BUDGET + rent(UpgradeableLoaderState::size_of_buffer(deployed.capacity))
        );
        // One byte too big still extends by the loader's minimum.
        let grows =
            required_balance(&Rent, deployed.capacity + 1, Some(&deployed)).expect("priced");
        assert_eq!(
            grows - fits,
            (rent(MIN_EXTEND_BYTES) - rent(0)) + (rent(1) - rent(0))
        );
    }

    #[test]
    fn a_deploy_is_usable_from_the_next_slot() {
        struct Advancing(Cell<u64>);
        impl Rpc for Advancing {
            fn get_slot(&self) -> Result<u64, ClientError> {
                let slot = self.0.get();
                self.0.set(slot + 1);
                Ok(slot)
            }
        }
        let rpc = Advancing(Cell::new(7));
        wait_until_usable(&rpc, Address::default(), 8).expect("usable");
        assert_eq!(rpc.0.get(), 10);
    }
}
