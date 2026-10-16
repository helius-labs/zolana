//! `init`, every step skipped when the chain already holds it, so a rerun resumes.

use anyhow::{anyhow, ensure, Context as _, Result};
use custom_ring_sdk::{CustomRing, CustomRingConfig, PolicyConfig, RingError, SourceOwner};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_keypair::X25519Pubkey;
use zolana_ring_client::rpc::{read_auditor_pubkey, write_auditor_pubkey};
use zolana_ring_policy::ListId;

use crate::{
    catalogue,
    config::{expand_tilde, RingConfig},
    deploy, line,
    policy::{self, CompiledPolicy, PolicySpec},
    status, Context, InitArgs, Trust,
};

const PRESENT: &str = "already present";
const CREATED: &str = "created";
const NEEDS_UPGRADE_AUTHORITY: &str =
    "the upgrade authority keypair is needed until the config authority holds the config";
const POLICY_DRIFT: &str =
    "the pinned policy differs from ring.toml, `zolana-ring policy set` replaces the table";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyChoice {
    File,
    Chain(X25519Pubkey),
    RingRpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigState {
    Missing,
    HeldByUpgradeAuthority,
    HeldByConfigAuthority,
}

pub fn run(ctx: &Context, args: InitArgs) -> Result<()> {
    let key_file = ctx.path(&expand_tilde(&args.auditor_pubkey_file)?);
    let compile = |spec: &PolicySpec| spec.compile(ctx.config.target);
    let policy = ctx.config.policy.as_ref().map(compile).transpose()?;
    let config_authority = ctx.funded_authority()?;
    let existing = ctx.block(ctx.ring.config(ctx.chain()))?;
    // A partial init still needs the upgrade authority to pin the policy.
    let held = existing
        .as_ref()
        .is_some_and(|config| config.authority == config_authority.pubkey());
    let upgrade_authority = match held && policy_config(ctx)?.is_some() {
        true => None,
        false => Some(ctx.config.upgrade_authority()?),
    };
    if let Some(deployer) = upgrade_authority.as_ref().filter(|_| existing.is_none()) {
        let program = ctx.ring.program_id();
        let data = deploy::program_data(ctx)?
            .with_context(|| format!("program {program} is not deployed, run `deploy` first"))?;
        let authority = data.upgrade_authority.with_context(|| {
            format!("program {program} is immutable and has no config, nothing can create one")
        })?;
        ensure!(
            authority == deployer.pubkey(),
            "program {program} is upgradeable by {authority}, ring.toml names {}",
            deployer.pubkey()
        );
    }
    let urls = ctx.config.urls();
    let choice = key_choice(
        key_file.exists(),
        !urls.ring_rpc_is_local(),
        args.local_auditor,
        existing.as_ref().map(|config| config.auditor_pubkey),
    )
    .with_context(|| {
        format!(
            "{} holds an auditor key, but the ring rpc at {} is not on this machine and holds its own. Pinning this key means only a ring rpc serving it can ever open the ring. Delete the file to take the service's key, or pass --local-auditor to keep it",
            key_file.display(),
            urls.ring_rpc
        )
    })?;
    let auditor_pk = match choice {
        KeyChoice::File => read_auditor_pubkey(&key_file)?,
        KeyChoice::Chain(auditor_pk) => {
            if key_file.exists() {
                let file = read_auditor_pubkey(&key_file)?;
                ensure!(
                    file == auditor_pk,
                    "{} holds auditor {}, the ring config pins {}. Delete the stale file",
                    key_file.display(),
                    hex::encode(file.as_bytes()),
                    hex::encode(auditor_pk.as_bytes())
                );
            }
            auditor_pk
        }
        KeyChoice::RingRpc => {
            let genesis_hash = ctx.rpc().genesis_hash()?;
            let authority = upgrade_authority
                .as_ref()
                .context(NEEDS_UPGRADE_AUTHORITY)?;
            let trust = ctx.trust(match args.trust_ring_rpc {
                true => Trust::Unpinned,
                false => Trust::Refuse,
            })?;
            ctx.ring_rpc()
                .release_auditor_key(ctx.ring.program_id(), genesis_hash, authority)?
                .require(trust)?
        }
    };
    let deposit_audit = args
        .deposit_audit
        .or_else(|| existing.is_none().then_some(ctx.config.deposit_audit));
    let deployer = upgrade_authority.as_ref();
    let has_policy = policy.is_some();
    let (config, authority) = create_config(
        ctx,
        deployer,
        config_authority,
        auditor_pk,
        has_policy,
        existing.as_ref(),
    )?;
    let policy = match &policy {
        None => "absent",
        Some(policy) => pin_policy(ctx, deployer, config_authority, policy)?,
    };
    let (ring, payer) = (ctx.ring, config_authority.pubkey());
    let send = |instruction| {
        ctx.send(&[config_authority], &[instruction])
            .map(|_| CREATED)
    };
    let key_registry = match ctx.block(ring.key_registry_root(ctx.chain()))? {
        Some(_) => PRESENT,
        None => send(ring.create_key_registry_root(payer, payer))?,
    };
    let deposit = match deposit_audit {
        Some(required) if ctx.block(ring.deposit_audit(ctx.chain()))? != required => {
            send(ring.set_deposit_audit(payer, payer, required)?)?
        }
        _ => PRESENT,
    };
    // The program registers a policy ring only after its policy is pinned.
    let spp_ring = match ctx.block(ring.spp_ring_config(ctx.chain()))? {
        Some(_) => PRESENT,
        None => send(ring.init_spp_ring_config(payer, payer, has_policy)).map(|_| "registered")?,
    };
    if let Some(required) = args.deposit_audit {
        RingConfig::set_deposit_audit(&ctx.config_path, required)?;
    }
    // Written after the chain agrees, so a failed init leaves no file a rerun takes for a local key.
    if choice == KeyChoice::RingRpc {
        write_auditor_pubkey(&key_file, &auditor_pk)?;
        line(
            "auditor pk",
            format_args!(
                "{} (from {}, written to {})",
                hex::encode(auditor_pk.as_bytes()),
                urls.ring_rpc,
                key_file.display()
            ),
        );
    }
    line("config", config);
    line("authority", authority);
    line("policy", policy);
    line("key registry", key_registry);
    line("deposit audit", deposit);
    line("spp ring", spp_ring);
    status::announce(&ctx.config);
    Ok(())
}

/// A config wins, its key is fixed for good. `None` is a local file against a hosted rpc,
/// pinning it means only a service holding that key can ever open the ring.
fn key_choice(
    file_present: bool,
    hosted_rpc: bool,
    local_auditor: bool,
    configured: Option<X25519Pubkey>,
) -> Option<KeyChoice> {
    match configured {
        Some(auditor_pk) => Some(KeyChoice::Chain(auditor_pk)),
        None if !file_present => Some(KeyChoice::RingRpc),
        None if hosted_rpc && !local_auditor => None,
        None => Some(KeyChoice::File),
    }
}

/// `Err` names a holder that is neither authority ring.toml names.
fn config_state(
    existing: Option<Address>,
    upgrade_authority: Option<Address>,
    config_authority: Address,
) -> Result<ConfigState, Address> {
    match existing {
        None => Ok(ConfigState::Missing),
        Some(holder) if holder == config_authority => Ok(ConfigState::HeldByConfigAuthority),
        Some(holder) if Some(holder) == upgrade_authority => {
            Ok(ConfigState::HeldByUpgradeAuthority)
        }
        Some(holder) => Err(holder),
    }
}

/// `create_config` accepts only the upgrade authority, a distinct config authority takes the
/// config over in the same transaction. Returns the config and authority outcomes.
fn create_config(
    ctx: &Context,
    deployer: Option<&Keypair>,
    config_authority: &Keypair,
    auditor_pk: X25519Pubkey,
    has_policy: bool,
    existing: Option<&CustomRingConfig>,
) -> Result<(&'static str, &'static str)> {
    let mismatch = |holder: Address, auditor: &X25519Pubkey| {
        anyhow!(
            "ring config exists under authority {holder} with auditor {}, ring.toml names another operator",
            hex::encode(auditor.as_bytes())
        )
    };
    if let Some(config) = existing {
        if config.auditor_pubkey != auditor_pk {
            return Err(mismatch(config.authority, &config.auditor_pubkey));
        }
        // The tier is immutable, transact dispatches on it.
        ensure!(
            config.has_policy == has_policy,
            "the ring is deployed as {}, ring.toml now selects the other tier, redeploy is not a tier change",
            if config.has_policy { "a policy ring" } else { "audit-only" }
        );
    }
    let target = config_authority.pubkey();
    let state = config_state(
        existing.map(|config| config.authority),
        deployer.map(Signer::pubkey),
        target,
    )
    .map_err(|holder| mismatch(holder, &auditor_pk))?;
    if state == ConfigState::HeldByConfigAuthority {
        return Ok((PRESENT, PRESENT));
    }
    let deployer = deployer.context(NEEDS_UPGRADE_AUTHORITY)?;
    let hand_over = ctx.ring.set_authority(deployer.pubkey(), target);
    if state == ConfigState::HeldByUpgradeAuthority {
        ctx.send(&[config_authority, deployer], &[hand_over])?;
        return Ok((PRESENT, "transferred"));
    }
    let mut instructions =
        vec![ctx
            .ring
            .create_config(target, deployer.pubkey(), auditor_pk, has_policy)?];
    let transfer = deployer.pubkey() != target;
    if transfer {
        instructions.push(hand_over);
    }
    ctx.send(&[config_authority, deployer], &instructions)?;
    Ok((CREATED, if transfer { "transferred" } else { PRESENT }))
}

/// Sources are pointed only over rows that agree, a drifted table stays untouched.
fn pin_policy(
    ctx: &Context,
    deployer: Option<&Keypair>,
    config_authority: &Keypair,
    policy: &CompiledPolicy,
) -> Result<&'static str> {
    for (list, curator) in &policy.shared_sources {
        catalogue::check_curator(ctx, *curator, *list, policy.address_tree)?;
    }
    let outcome = match policy_config(ctx)? {
        Some(_) => PRESENT,
        None => {
            let deployer = deployer.context(NEEDS_UPGRADE_AUTHORITY)?;
            let create = |sources: &[(ListId, CustomRing)]| {
                ctx.ring.create_policy(
                    config_authority.pubkey(),
                    deployer.pubkey(),
                    policy.address_tree,
                    &policy.rules,
                    sources,
                )
            };
            // Curators past the transaction size are pointed one by one below.
            let instruction = match create(&policy.shared_sources) {
                Err(RingError::TransactionTooLarge { .. }) if !policy.shared_sources.is_empty() => {
                    create(&[])?
                }
                result => result?,
            };
            ctx.send(&[config_authority, deployer], &[instruction])?;
            CREATED
        }
    };
    let config = pinned(ctx)?;
    policy::verify_rows(policy, &config).context(POLICY_DRIFT)?;
    let mut pointed = false;
    for (list, curator) in &policy.shared_sources {
        let outcome = if config.source_for(*list) == Some(curator.namespace_pda()) {
            PRESENT
        } else {
            let point = ctx.ring.set_source_owner(
                config_authority.pubkey(),
                *list,
                SourceOwner::Shared(*curator),
            )?;
            ctx.send(&[config_authority], &[point])?;
            pointed = true;
            CREATED
        };
        line(
            list.name(),
            format_args!("curator {} {outcome}", curator.program_id()),
        );
    }
    let config = if pointed { pinned(ctx)? } else { config };
    policy::verify_sources(ctx.ring, policy, &config).context(POLICY_DRIFT)?;
    Ok(outcome)
}

fn policy_config(ctx: &Context) -> Result<Option<PolicyConfig>> {
    Ok(ctx.block(ctx.ring.policy_config(ctx.chain()))?)
}

fn pinned(ctx: &Context) -> Result<PolicyConfig> {
    let program = ctx.ring.program_id();
    policy_config(ctx)?
        .with_context(|| format!("the policy of {program} is not pinned after create_policy"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_wins_over_the_file_and_the_service() {
        let pinned = zolana_keypair::X25519Secret::new().pubkey();
        for file_present in [true, false] {
            for hosted_rpc in [true, false] {
                for local_auditor in [true, false] {
                    assert_eq!(
                        key_choice(file_present, hosted_rpc, local_auditor, Some(pinned)),
                        Some(KeyChoice::Chain(pinned))
                    );
                }
            }
        }
    }

    #[test]
    fn without_a_config_the_file_is_taken_only_where_the_service_wrote_it() {
        for hosted_rpc in [true, false] {
            for local_auditor in [true, false] {
                assert_eq!(
                    key_choice(false, hosted_rpc, local_auditor, None),
                    Some(KeyChoice::RingRpc)
                );
            }
        }
        assert_eq!(key_choice(true, false, false, None), Some(KeyChoice::File));
        assert_eq!(key_choice(true, false, true, None), Some(KeyChoice::File));
        assert_eq!(key_choice(true, true, true, None), Some(KeyChoice::File));
        assert_eq!(key_choice(true, true, false, None), None);
    }

    #[test]
    fn the_config_moves_from_the_upgrade_authority_to_the_config_authority_once() {
        let deployer = Address::new_from_array([1; 32]);
        let target = Address::new_from_array([2; 32]);
        let stranger = Address::new_from_array([3; 32]);
        let state = |existing, upgrade_authority| config_state(existing, upgrade_authority, target);
        assert_eq!(state(None, Some(deployer)), Ok(ConfigState::Missing));
        assert_eq!(state(None, None), Ok(ConfigState::Missing));
        assert_eq!(
            state(Some(deployer), Some(deployer)),
            Ok(ConfigState::HeldByUpgradeAuthority)
        );
        assert_eq!(
            state(Some(target), Some(deployer)),
            Ok(ConfigState::HeldByConfigAuthority)
        );
        assert_eq!(
            state(Some(target), None),
            Ok(ConfigState::HeldByConfigAuthority)
        );
        assert_eq!(state(Some(deployer), None), Err(deployer));
        assert_eq!(state(Some(stranger), Some(deployer)), Err(stranger));
        assert_eq!(
            config_state(Some(deployer), Some(deployer), deployer),
            Ok(ConfigState::HeldByConfigAuthority)
        );
    }
}
