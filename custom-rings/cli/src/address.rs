//! `address`, the `zolana:` payment request an anonymous ring pays a member through.

use anyhow::Result;
use solana_address::Address;
use zolana_keypair::{KeypairError, RingAddress, RingPaymentRequest, ShieldedKeypair};

use crate::{file, AddressArgs, Context};

pub fn run(ctx: &Context, args: AddressArgs) -> Result<()> {
    let keypair = match &args.keypair {
        Some(path) => file::read_keypair(&ctx.path(path))?,
        None => ctx.sender()?,
    };
    let member = ShieldedKeypair::from_keypair(&keypair)?;
    let address = ring_address(&member, ctx.ring.program_id(), args.index)?;
    println!("{}", args.request(address));
    Ok(())
}

/// The member's `index`th address, the wallet scan reads inbox indices in issue order.
pub fn ring_address(
    member: &ShieldedKeypair,
    ring_program_id: Address,
    index: u32,
) -> Result<RingAddress, KeypairError> {
    Ok(RingAddress {
        recipient: member.shielded_address()?,
        ring_program_id,
        inbox_secret: member.viewing_key.inbox_secret(index)?,
    })
}

impl AddressArgs {
    fn request(self, address: RingAddress) -> RingPaymentRequest {
        RingPaymentRequest {
            address,
            amount: self.amount,
            mint: self.mint.map(|mint| mint.0),
            label: self.label,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use serde::Deserialize;
    use zolana_keypair::{InboxSecret, ShieldedAddress, SigningKey, ViewingKey};

    use super::*;
    use crate::{Cli, Command};

    const VECTORS: &str = include_str!("../../../test-vectors/ring_address.json");

    #[derive(Deserialize)]
    struct Vectors {
        valid: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        name: String,
        uri: String,
        recipient: String,
        ring_program_id: String,
        inbox_secret: String,
        amount: Option<String>,
        mint: Option<String>,
        label: Option<String>,
    }

    fn vectors() -> Vec<Case> {
        serde_json::from_str::<Vectors>(VECTORS).unwrap().valid
    }

    fn inbox_secret(hex_secret: &str) -> InboxSecret {
        InboxSecret::from_bytes(hex::decode(hex_secret).unwrap().try_into().unwrap())
    }

    fn parse(flags: &[&str]) -> AddressArgs {
        let argv = ["zolana-ring", "address"].iter().chain(flags).copied();
        match Cli::try_parse_from(argv).unwrap().command {
            Command::Address(args) => args,
            _ => panic!("address"),
        }
    }

    #[test]
    fn the_printed_request_matches_the_keypair_vectors() {
        for case in vectors() {
            let recipient: [u8; 99] = hex::decode(&case.recipient).unwrap().try_into().unwrap();
            let address = RingAddress {
                recipient: ShieldedAddress::from_bytes(&recipient).unwrap(),
                ring_program_id: case.ring_program_id.parse().unwrap(),
                inbox_secret: inbox_secret(&case.inbox_secret),
            };
            let mut flags = Vec::new();
            for (flag, value) in [
                ("--amount", &case.amount),
                ("--mint", &case.mint),
                ("--label", &case.label),
            ] {
                if let Some(value) = value {
                    flags.extend([flag, value.as_str()]);
                }
            }
            let printed = parse(&flags).request(address).to_string();
            assert_eq!(printed, case.uri, "{}", case.name);
        }
    }

    #[test]
    fn index_selects_the_inbox_secret_the_vectors_derive() {
        let case = &vectors()[0];
        let member = ShieldedKeypair::with_viewing_key(
            SigningKey::from_ed25519_bytes(&[7; 32]),
            ViewingKey::from_bytes(&[0x21; 32]),
        )
        .unwrap();
        let program: Address = case.ring_program_id.parse().unwrap();
        let first = ring_address(&member, program, parse(&[]).index).unwrap();
        assert_eq!(first.inbox_secret, inbox_secret(&case.inbox_secret));
        assert_eq!(first.recipient, member.shielded_address().unwrap());
        assert_eq!(first.ring_program_id, program);
        let second = ring_address(&member, program, parse(&["--index", "1"]).index).unwrap();
        assert_eq!(second.recipient, first.recipient);
        assert_ne!(second.inbox_secret, first.inbox_secret);
    }
}
