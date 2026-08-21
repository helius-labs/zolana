use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result};
use bytemuck::try_from_bytes;
use clap::{Parser, Subcommand};
use custom_ring_sdk::{
    CreateConfig, CustomRing, GrantReader, InitSppRingConfig, ReaderKey, RevokeReader,
};
use solana_address::Address;
use solana_keypair::{read_keypair_file, Keypair};
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};
use zolana_interface::{pda, state::RingConfig, RING_AUTH_PDA_SEED};
use zolana_keypair::P256Pubkey;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    rpc_url: String,
    #[arg(long, default_value = "{{authority_keypair}}")]
    authority: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long, default_value = "keys/auditor.key.pub")]
        auditor_pubkey_file: PathBuf,
    },
    GrantReader {
        reader: ReaderKey,
    },
    RevokeReader {
        reader: ReaderKey,
    },
    Status,
}

struct RingOperator {
    rpc: SolanaRpc,
    authority: Keypair,
    ring: CustomRing,
}

impl RingOperator {
    fn load(cli: &Cli) -> Result<Self> {
        let authority_path = expand_home(&cli.authority)?;
        let authority = read_keypair_file(&authority_path)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
            .with_context(|| format!("cannot read {}", authority_path.display()))?;
        Ok(Self {
            rpc: SolanaRpc::new(cli.rpc_url.clone()),
            authority,
            ring: CustomRing::new(Address::from_str(
                "{{program_id}}",
            )?),
        })
    }

    fn run(&self, command: Command) -> Result<()> {
        match command {
            Command::Init {
                auditor_pubkey_file,
            } => self.init(&auditor_pubkey_file),
            Command::GrantReader { reader } => self.grant(reader),
            Command::RevokeReader { reader } => self.revoke(reader),
            Command::Status => self.status(),
        }
    }

    fn init(&self, auditor_pubkey_file: &Path) -> Result<()> {
        let auditor_pubkey = read_auditor_pubkey(auditor_pubkey_file)?;
        match self.ring.read_config(&self.rpc)? {
            Some(config)
                if config.auditor_pubkey != auditor_pubkey
                    || config.authority != self.authority.pubkey() =>
            {
                anyhow::bail!("custom ring config does not match the operator")
            }
            Some(_) => {}
            None => self.send(
                CreateConfig {
                    ring: self.ring,
                    payer: self.authority.pubkey(),
                    authority: self.authority.pubkey(),
                    auditor_pubkey,
                }
                .instruction()?,
            )?,
        }
        if !self.ring_registration()? {
            self.send(
                InitSppRingConfig {
                    ring: self.ring,
                    payer: self.authority.pubkey(),
                    authority: self.authority.pubkey(),
                }
                .instruction(),
            )?;
        }
        self.status()
    }

    fn grant(&self, reader: ReaderKey) -> Result<()> {
        if self.ring.read_reader_record(&self.rpc, &reader)?.is_none() {
            self.send(
                GrantReader {
                    ring: self.ring,
                    payer: self.authority.pubkey(),
                    authority: self.authority.pubkey(),
                    reader,
                }
                .instruction()?,
            )?;
        }
        Ok(())
    }

    fn revoke(&self, reader: ReaderKey) -> Result<()> {
        if self.ring.read_reader_record(&self.rpc, &reader)?.is_some() {
            self.send(
                RevokeReader {
                    ring: self.ring,
                    authority: self.authority.pubkey(),
                    reader,
                    rent_recipient: self.authority.pubkey(),
                }
                .instruction()?,
            )?;
        }
        Ok(())
    }

    fn status(&self) -> Result<()> {
        println!("program {}", self.ring.program_id());
        println!("authority {}", self.authority.pubkey());
        println!(
            "deployed {}",
            self.rpc.get_account(self.ring.program_id())?.is_some()
        );
        println!("configured {}", self.ring.read_config(&self.rpc)?.is_some());
        println!("registered {}", self.ring_registration()?);
        Ok(())
    }

    fn ring_registration(&self) -> Result<bool> {
        let address = self.ring.ring_auth_pda();
        let Some(account) = self.rpc.get_account(address)? else {
            return Ok(false);
        };
        let invalid = || anyhow::anyhow!("shielded pool ring registration is invalid");
        if account.owner.to_bytes() != pda::shielded_pool_program_id().to_bytes()
            || account.data.len() != RingConfig::SIZE
        {
            return Err(invalid());
        }
        let config = try_from_bytes::<RingConfig>(&account.data).map_err(|_| invalid())?;
        let bump = solana_address::Address::find_program_address(
            &[RING_AUTH_PDA_SEED],
            &self.ring.program_id(),
        )
        .1;
        if !config.has_discriminator()
            || config.program_id != self.ring.program_id()
            || config.authority != self.authority.pubkey()
            || config.bump != bump
        {
            return Err(invalid());
        }
        Ok(true)
    }

    fn send(&self, instruction: solana_instruction::Instruction) -> Result<()> {
        self.rpc.create_and_send_transaction(
            &[instruction],
            self.authority.pubkey(),
            &[&self.authority],
        )?;
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    RingOperator::load(&cli)?.run(cli.command)
}

fn read_auditor_pubkey(path: &Path) -> Result<P256Pubkey> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let bytes: [u8; 33] = hex::decode(text.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("auditor public key must have 33 bytes"))?;
    Ok(P256Pubkey::from_bytes(bytes)?)
}

fn expand_home(path: &Path) -> Result<PathBuf> {
    let Ok(rest) = path.strip_prefix("~") else {
        return Ok(path.to_path_buf());
    };
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(rest))
}
