//! `address`, the `zolana:` payment request an anonymous ring pays a member through.

use anyhow::{ensure, Result};
use solana_address::Address;
use zolana_client::{AnonymousRingState, ADDRESS_GAP};
use zolana_keypair::{KeypairError, RingAddress, RingPaymentRequest, ShieldedKeypair};

use crate::{file, AddressArgs, Context};

pub fn run(ctx: &Context, args: AddressArgs) -> Result<()> {
    let keypair = match &args.keypair {
        Some(path) => file::read_keypair(&ctx.path(path))?,
        None => ctx.sender()?,
    };
    let member = ShieldedKeypair::from_keypair(&keypair)?;
    // Stored before it prints, a payer never holds an address the scan skips.
    let index = ctx
        .anonymous_ring_store(&member)
        .update(|state| args.issue(state))?;
    let address = ring_address(&member, ctx.ring.program_id(), index)?;
    eprintln!("address index {index}");
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
    fn issue(&self, state: &mut AnonymousRingState) -> Result<u32> {
        let index = self.index.unwrap_or(state.issued_addresses());
        let gap_end = state.issued_addresses().saturating_add(ADDRESS_GAP);
        ensure!(
            index < gap_end || self.beyond_gap,
            "index {index} is past the discovery gap at {gap_end}, pass --beyond-gap to issue it"
        );
        state.issue(index)?;
        Ok(index)
    }

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
    use zolana_client::ClientError;
    use zolana_keypair::{InboxSecret, ShieldedAddress, SigningKey, ViewingKey};

    use super::*;
    use crate::{
        wallet::fixtures::{
            inbox_tag, keypair, AnonymousTransfer, Indexer, Member, Paid, RingUtxo,
        },
        Cli, Command,
    };

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
        let mut state = AnonymousRingState::default();
        let first = ring_address(&member, program, parse(&[]).issue(&mut state).unwrap()).unwrap();
        assert_eq!(first.inbox_secret, inbox_secret(&case.inbox_secret));
        assert_eq!(first.recipient, member.shielded_address().unwrap());
        assert_eq!(first.ring_program_id, program);
        let second = ring_address(&member, program, parse(&[]).issue(&mut state).unwrap()).unwrap();
        assert_eq!(second.recipient, first.recipient);
        assert_ne!(second.inbox_secret, first.inbox_secret);
    }

    #[test]
    fn address_issues_in_order_and_refuses_an_index_past_the_gap() {
        let mut state = AnonymousRingState::default();
        let mut issue = |flags: &[&str]| parse(flags).issue(&mut state);
        assert_eq!(issue(&[]).unwrap(), 0);
        assert_eq!(issue(&[]).unwrap(), 1);
        assert_eq!(issue(&["--index", "0"]).unwrap(), 0);
        let last_in_gap = 1 + ADDRESS_GAP;
        assert_eq!(
            issue(&["--index", &last_in_gap.to_string()]).unwrap(),
            last_in_gap
        );
        let far = (last_in_gap + 1 + ADDRESS_GAP).to_string();
        let refused = issue(&["--index", &far]).unwrap_err().to_string();
        assert!(refused.contains("--beyond-gap"), "{refused}");
        assert!(issue(&["--index", &far, "--beyond-gap"]).is_ok());
        let huge = issue(&["--index", &u32::MAX.to_string(), "--beyond-gap"]).unwrap_err();
        assert!(matches!(
            huge.downcast_ref::<ClientError>(),
            Some(ClientError::TooManyIssuedAddresses { count }) if *count == 1 << 32
        ));
        assert_eq!(state.issued_addresses(), last_in_gap + 2 + ADDRESS_GAP);
        assert!(Cli::try_parse_from(["zolana-ring", "address", "--beyond-gap"]).is_err());
    }

    #[test]
    fn an_issued_index_past_the_gap_is_read_by_routine_sync() {
        let member = Member::new(1, "far-address");
        let far = 2 * ADDRESS_GAP;
        let paid = RingUtxo::new(&member.keys, 9);
        let indexer = Indexer(vec![AnonymousTransfer {
            payer: &keypair(2),
            nullifiers: vec![[9; 32]],
            outputs: vec![Paid {
                to: &member.keys,
                output: &paid,
                tag: inbox_tag(&member.keys, far),
            }],
        }
        .transaction()]);
        assert_eq!(member.scan(&indexer).utxos().count(), 0);

        let index = far.to_string();
        let issued = member
            .store
            .update(|state| parse(&["--index", &index, "--beyond-gap"]).issue(state))
            .unwrap();
        assert_eq!(issued, far);
        let found: Vec<_> = member
            .scan(&indexer)
            .utxos()
            .map(|entry| entry.utxo_hash)
            .collect();
        assert_eq!(found, vec![paid.hash]);
        assert_eq!(member.store.load().unwrap().issued_addresses(), far + 1);
    }
}
