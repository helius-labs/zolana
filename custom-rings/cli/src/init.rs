//! `init`, every step skipped when the chain already holds it, so a rerun resumes.

use anyhow::{anyhow, ensure, Context as _, Result};
use custom_ring_sdk::{
    CustomRing, CustomRingConfig, ListRegistry, RingError, RingSetup, SourceOwner,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_keypair::X25519Pubkey;
use zolana_ring_client::rpc::{read_auditor_pubkey, write_auditor_pubkey};
use zolana_ring_policy::ListId;

use crate::{
    catalogue,
    config::{expand_tilde, ModeName},
    controls, deploy, line,
    policy::{self, CompiledPolicy, PolicySpec},
    status, Context, InitArgs, Trust,
};

const PRESENT: &str = "already present";
const CREATED: &str = "created";
const TRANSFERRED: &str = "transferred";
const NEEDS_UPGRADE_AUTHORITY: &str =
    "the upgrade authority keypair is needed until the config authority holds the config";
const POLICY_DRIFT: &str =
    "the pinned policy differs from ring.toml, `zolana-ring policy set` replaces the table";

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeySelection {
    file_present: bool,
    hosted_rpc: bool,
    local_auditor: bool,
    configured: Option<X25519Pubkey>,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyChoice {
    File,
    Chain(X25519Pubkey),
    RingRpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a local auditor key file against a hosted ring rpc")]
struct StrayLocalKey;

/// `create_config` accepts only the upgrade authority, so a distinct config
/// authority takes the config over in the same transaction.
#[must_use]
struct ConfigCreation<'a> {
    deployer: Option<&'a Keypair>,
    config_authority: &'a Keypair,
    auditor_pk: X25519Pubkey,
    has_policy: bool,
    mode: ModeName,
    existing: Option<&'a CustomRingConfig>,
}

struct ConfigOutcome {
    config: &'static str,
    authority: &'static str,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConfigOwnership {
    existing: Option<Address>,
    upgrade_authority: Option<Address>,
    config_authority: Address,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigState {
    Missing,
    HeldByUpgradeAuthority,
    HeldByConfigAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ForeignConfigAuthority(Address);

#[must_use]
struct PolicyPin<'a> {
    authority: &'a Keypair,
    policy: &'a CompiledPolicy,
}

pub fn run(ctx: &Context, args: InitArgs) -> Result<()> {
    let key_file = ctx.path(&expand_tilde(&args.auditor_pubkey_file)?);
    let compile = |spec: &PolicySpec| spec.compile(ctx.config.target);
    let policy = ctx.config.policy.as_ref().map(compile).transpose()?;
    let config_authority = ctx.funded_authority()?;
    let existing = ctx.block(ctx.ring.config(ctx.chain()))?;
    // Only the upgrade authority creates the config, the config authority pins the rest.
    let held = existing
        .as_ref()
        .is_some_and(|config| config.authority == config_authority.pubkey());
    let upgrade_authority = match held {
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
    let selection = KeySelection {
        file_present: key_file.exists(),
        hosted_rpc: !urls.ring_rpc_is_local(),
        local_auditor: args.local_auditor,
        configured: existing.as_ref().map(|config| config.auditor_pubkey),
    };
    let choice = selection.decide().with_context(|| {
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
    let has_policy = policy.is_some();
    let created = ConfigCreation {
        deployer: upgrade_authority.as_ref(),
        config_authority,
        auditor_pk,
        has_policy,
        mode: ctx.config.mode,
        existing: existing.as_ref(),
    }
    .send(ctx)?;
    let (ring, payer) = (ctx.ring, config_authority.pubkey());
    let send = |instruction| {
        ctx.send(&[config_authority], &[instruction])
            .map(|_| CREATED)
    };
    // The registry holds the policy, it precedes the policy pin.
    let member_registry = match ctx.block(ring.registry(ctx.chain()))? {
        Some(_) => PRESENT,
        None => send(ring.create_member_registry(payer, payer))?,
    };
    let policy = match &policy {
        None => "absent",
        Some(policy) => PolicyPin {
            authority: config_authority,
            policy,
        }
        .send(ctx)?,
    };
    // The program registers a policy ring only after its policy is pinned.
    let spp_ring = match ctx.block(ring.registration(ctx.chain()))? {
        Some(_) => PRESENT,
        None => send(ring.init_spp_ring_config(payer, payer, has_policy)).map(|_| "registered")?,
    };
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
    line("config", created.config);
    line("authority", created.authority);
    line("member registry", member_registry);
    line("policy", policy);
    line("spp ring", spp_ring);
    controls::print_insert_fee(&ctx.ring_config()?);
    status::announce(&ctx.config);
    Ok(())
}

impl KeySelection {
    /// A config wins, its key is fixed and a rerun must not touch the service.
    fn decide(self) -> Result<KeyChoice, StrayLocalKey> {
        match self.configured {
            Some(auditor_pk) => Ok(KeyChoice::Chain(auditor_pk)),
            None if !self.file_present => Ok(KeyChoice::RingRpc),
            None if self.hosted_rpc && !self.local_auditor => Err(StrayLocalKey),
            None => Ok(KeyChoice::File),
        }
    }
}

impl ConfigCreation<'_> {
    fn send(self, ctx: &Context) -> Result<ConfigOutcome> {
        let mismatch = |holder: Address, auditor: &X25519Pubkey| {
            anyhow!(
                "ring config exists under authority {holder} with auditor {}, ring.toml names another operator",
                hex::encode(auditor.as_bytes())
            )
        };
        if let Some(config) = self.existing {
            if config.auditor_pubkey != self.auditor_pk {
                return Err(mismatch(config.authority, &config.auditor_pubkey));
            }
            // The tier is immutable, transact dispatches on it.
            ensure!(
                config.has_policy == self.has_policy,
                "the ring is deployed as {}, ring.toml now selects the other tier, redeploy is not a tier change",
                if config.has_policy { "a policy ring" } else { "audit-only" }
            );
            ensure!(
                ModeName::of(config.mode) == self.mode,
                "ring.toml selects the {} mode, the deployed config has another, redeploy is not a mode change",
                self.mode
            );
        }
        let target = self.config_authority.pubkey();
        let state = ConfigOwnership {
            existing: self.existing.map(|config| config.authority),
            upgrade_authority: self.deployer.map(Signer::pubkey),
            config_authority: target,
        }
        .decide()
        .map_err(|ForeignConfigAuthority(holder)| mismatch(holder, &self.auditor_pk))?;
        if state == ConfigState::HeldByConfigAuthority {
            return Ok(ConfigOutcome {
                config: PRESENT,
                authority: PRESENT,
            });
        }
        let deployer = self.deployer.context(NEEDS_UPGRADE_AUTHORITY)?;
        let hand_over = ctx.ring.set_authority(deployer.pubkey(), target);
        if state == ConfigState::HeldByUpgradeAuthority {
            ctx.send(&[self.config_authority, deployer], &[hand_over])?;
            return Ok(ConfigOutcome {
                config: PRESENT,
                authority: TRANSFERRED,
            });
        }
        let setup = RingSetup {
            auditor_pubkey: self.auditor_pk,
            has_policy: self.has_policy,
            anonymous: self.mode == ModeName::Anonymous,
        };
        let mut instructions = vec![ctx.ring.create_config(target, deployer.pubkey(), setup)?];
        let transfer = deployer.pubkey() != target;
        if transfer {
            instructions.push(hand_over);
        }
        ctx.send(&[self.config_authority, deployer], &instructions)?;
        Ok(ConfigOutcome {
            config: CREATED,
            authority: if transfer { TRANSFERRED } else { PRESENT },
        })
    }
}

impl ConfigOwnership {
    fn decide(self) -> Result<ConfigState, ForeignConfigAuthority> {
        match self.existing {
            None => Ok(ConfigState::Missing),
            Some(holder) if holder == self.config_authority => {
                Ok(ConfigState::HeldByConfigAuthority)
            }
            Some(holder) if Some(holder) == self.upgrade_authority => {
                Ok(ConfigState::HeldByUpgradeAuthority)
            }
            Some(holder) => Err(ForeignConfigAuthority(holder)),
        }
    }
}

impl PolicyPin<'_> {
    /// Sources are pointed only over rows that agree, a drifted table stays untouched.
    fn send(self, ctx: &Context) -> Result<&'static str> {
        let Self { authority, policy } = self;
        for (list, curator) in &policy.shared_sources {
            catalogue::check_curator(ctx, *curator, *list)?;
        }
        let outcome = match policy::pinned_if_any(ctx)? {
            Some(_) => PRESENT,
            None => {
                let create = |sources: &[(ListId, CustomRing)]| {
                    ctx.ring
                        .create_policy(authority.pubkey(), &policy.rules, sources)
                };
                // Curators past the transaction size are pointed one by one below.
                let instruction = match create(&policy.shared_sources) {
                    Err(RingError::TransactionTooLarge { .. })
                        if !policy.shared_sources.is_empty() =>
                    {
                        create(&[])?
                    }
                    result => result?,
                };
                ctx.send(&[authority], &[instruction])?;
                CREATED
            }
        };
        let pinned = policy::pinned(ctx)?;
        policy::verify_rows(policy, &pinned).context(POLICY_DRIFT)?;
        let mut pointed = false;
        for (list, curator) in &policy.shared_sources {
            let outcome = if pinned.registry.registry_for(*list)
                == Some(ListRegistry::Curator(curator.registry_pda()))
            {
                PRESENT
            } else {
                let point = ctx.ring.set_source_owner(
                    authority.pubkey(),
                    *list,
                    SourceOwner::Shared(*curator),
                )?;
                ctx.send(&[authority], &[point])?;
                pointed = true;
                CREATED
            };
            line(
                list.name(),
                format_args!("curator {} {outcome}", curator.program_id()),
            );
        }
        let pinned = if pointed {
            policy::pinned(ctx)?
        } else {
            pinned
        };
        policy::verify_sources(ctx.ring, policy, &pinned).context(POLICY_DRIFT)?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNCONFIGURED: KeySelection = KeySelection {
        file_present: false,
        hosted_rpc: false,
        local_auditor: false,
        configured: None,
    };

    #[test]
    fn a_config_wins_over_the_file_and_the_service() {
        let pinned = zolana_keypair::X25519Keypair::new().pubkey();
        for file_present in [true, false] {
            for hosted_rpc in [true, false] {
                for local_auditor in [true, false] {
                    let selection = KeySelection {
                        file_present,
                        hosted_rpc,
                        local_auditor,
                        configured: Some(pinned),
                    };
                    assert_eq!(selection.decide(), Ok(KeyChoice::Chain(pinned)));
                }
            }
        }
    }

    #[test]
    fn without_a_config_the_file_is_taken_only_where_the_service_wrote_it() {
        for hosted_rpc in [true, false] {
            for local_auditor in [true, false] {
                let selection = KeySelection {
                    hosted_rpc,
                    local_auditor,
                    ..UNCONFIGURED
                };
                assert_eq!(selection.decide(), Ok(KeyChoice::RingRpc));
            }
        }
        let file = KeySelection {
            file_present: true,
            ..UNCONFIGURED
        };
        assert_eq!(file.decide(), Ok(KeyChoice::File));
        let kept = KeySelection {
            local_auditor: true,
            ..file
        };
        assert_eq!(kept.decide(), Ok(KeyChoice::File));
        let hosted_kept = KeySelection {
            hosted_rpc: true,
            ..kept
        };
        assert_eq!(hosted_kept.decide(), Ok(KeyChoice::File));
        let hosted = KeySelection {
            hosted_rpc: true,
            ..file
        };
        assert_eq!(hosted.decide(), Err(StrayLocalKey));
    }

    #[test]
    fn the_config_moves_from_the_upgrade_authority_to_the_config_authority_once() {
        let deployer = Address::new_from_array([1; 32]);
        let target = Address::new_from_array([2; 32]);
        let stranger = Address::new_from_array([3; 32]);
        let missing = ConfigOwnership {
            existing: None,
            upgrade_authority: Some(deployer),
            config_authority: target,
        };
        assert_eq!(missing.decide(), Ok(ConfigState::Missing));
        let no_deployer = ConfigOwnership {
            upgrade_authority: None,
            ..missing
        };
        assert_eq!(no_deployer.decide(), Ok(ConfigState::Missing));
        let deployed = ConfigOwnership {
            existing: Some(deployer),
            ..missing
        };
        assert_eq!(deployed.decide(), Ok(ConfigState::HeldByUpgradeAuthority));
        let handed_over = ConfigOwnership {
            existing: Some(target),
            ..missing
        };
        assert_eq!(handed_over.decide(), Ok(ConfigState::HeldByConfigAuthority));
        let handed_over_no_deployer = ConfigOwnership {
            existing: Some(target),
            ..no_deployer
        };
        assert_eq!(
            handed_over_no_deployer.decide(),
            Ok(ConfigState::HeldByConfigAuthority)
        );
        let deployed_no_deployer = ConfigOwnership {
            existing: Some(deployer),
            ..no_deployer
        };
        assert_eq!(
            deployed_no_deployer.decide(),
            Err(ForeignConfigAuthority(deployer))
        );
        let foreign = ConfigOwnership {
            existing: Some(stranger),
            ..missing
        };
        assert_eq!(foreign.decide(), Err(ForeignConfigAuthority(stranger)));
        let one_key = ConfigOwnership {
            existing: Some(deployer),
            upgrade_authority: Some(deployer),
            config_authority: deployer,
        };
        assert_eq!(one_key.decide(), Ok(ConfigState::HeldByConfigAuthority));
    }
}
