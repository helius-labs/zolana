//! `address`, the `zolana:` payment request an anonymous ring pays a member through.

use std::str::FromStr;

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_interface::RingMode;
use solana_address::Address;
use zolana_client::{AnonymousRingState, ADDRESS_GAP};
use zolana_keypair::{Pairing, PairingRow, RingAddress, RingPaymentRequest, ShieldedKeypair};

use crate::{file, AddressArgs, Context, Mint};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingRowArg(PairingRow);

pub fn run(ctx: &Context, args: AddressArgs) -> Result<()> {
    let config = ctx.ring_config()?;
    ensure!(
        config.mode == RingMode::Anonymous,
        "a `zolana:` address pays an anonymous ring, ring {} is not one",
        ctx.ring.program_id()
    );
    let keypair = match &args.keypair {
        Some(path) => file::read_keypair(&ctx.path(path))?,
        None => ctx.sender()?,
    };
    let member = ShieldedKeypair::from_keypair(&keypair)?;
    let store = ctx.anonymous_ring_store(&member, &config);
    // Stored before it prints, a payer never holds an address the scan skips.
    let address = store.update(|state| {
        let index = args.issue(state)?;
        eprintln!("address index {index}");
        state
            .address(&member, index)?
            .context("the issued index has no address")
    })?;
    println!("{}", args.request(address));
    Ok(())
}

/// Under the default pairing, recorded in no store.
pub fn ring_address(
    member: &ShieldedKeypair,
    ring_program_id: Address,
    index: u32,
) -> Result<RingAddress> {
    let mut state = AnonymousRingState::new(ring_program_id, 0);
    state.issue(index, Pairing::default())?;
    state
        .address(member, index)?
        .context("the issued index has no address")
}

impl AddressArgs {
    /// A reprinted index keeps the pairing its payers hold.
    fn issue(&self, state: &mut AnonymousRingState) -> Result<u32> {
        let next = state
            .issued()
            .last()
            .map_or(0, |issued| issued.index.saturating_add(1));
        let index = self.index.unwrap_or(next);
        let gap_end = next.saturating_add(ADDRESS_GAP);
        ensure!(
            index < gap_end || self.beyond_gap,
            "index {index} is past the discovery gap at {gap_end}, pass --beyond-gap to issue it"
        );
        let issued = state
            .issued()
            .iter()
            .find(|issued| issued.index == index)
            .map(|issued| issued.pairing.clone());
        let pairing = match (self.pairing()?, issued) {
            (Some(asked), Some(issued)) if asked != issued => bail!(
                "index {index} is issued with another pairing, payers holding the address keep it"
            ),
            (Some(pairing), _) | (None, Some(pairing)) => pairing,
            (None, None) => Pairing::default(),
        };
        state.issue(index, pairing)?;
        Ok(index)
    }

    fn pairing(&self) -> Result<Option<Pairing>> {
        if self.no_pairing {
            return Ok(Some(Pairing::off()));
        }
        if self.pairing.is_empty() {
            return Ok(None);
        }
        let rows = self.pairing.iter().map(|row| row.0).collect();
        Ok(Some(Pairing::new(rows)?))
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

impl FromStr for PairingRowArg {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        let (mint, min_amount) = value.split_once(':').ok_or("expected <mint>:<min>")?;
        let mint = match mint {
            "any" => PairingRow::ANY.mint,
            mint => {
                let Mint(mint) = mint.parse()?;
                // The all-zero mint that encodes SOL matches every asset in a pairing row.
                if mint == PairingRow::ANY.mint {
                    return Err("a pairing row cannot single out SOL, write any:<min>".to_owned());
                }
                mint
            }
        };
        let min_amount = min_amount
            .parse()
            .map_err(|_| format!("{min_amount} is not an amount"))?;
        Ok(Self(PairingRow { mint, min_amount }))
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use serde::Deserialize;
    use zolana_client::ClientError;
    use zolana_keypair::{KeypairError, ShieldedAddress};

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
        pairing: Vec<Row>,
        amount: Option<String>,
        mint: Option<String>,
        label: Option<String>,
    }

    #[derive(Deserialize)]
    struct Row {
        mint: String,
        min_amount: String,
    }

    fn parse(flags: &[&str]) -> AddressArgs {
        try_parse(flags).unwrap()
    }

    fn try_parse(flags: &[&str]) -> Result<AddressArgs, clap::Error> {
        let argv = ["zolana-ring", "address"].iter().chain(flags).copied();
        Cli::try_parse_from(argv).map(|cli| match cli.command {
            Command::Address(args) => args,
            _ => panic!("address"),
        })
    }

    #[test]
    fn the_printed_request_matches_the_keypair_vectors() {
        for case in serde_json::from_str::<Vectors>(VECTORS).unwrap().valid {
            let recipient = hex::decode(&case.recipient).unwrap().try_into().unwrap();
            let rows: Vec<String> = case
                .pairing
                .iter()
                .map(|row| match row.mint.parse::<Address>().unwrap() {
                    mint if mint == PairingRow::ANY.mint => format!("any:{}", row.min_amount),
                    mint => format!("{mint}:{}", row.min_amount),
                })
                .collect();
            let mut flags = Vec::new();
            for row in &rows {
                flags.extend(["--pairing", row.as_str()]);
            }
            if rows.is_empty() {
                flags.push("--no-pairing");
            }
            for (flag, value) in [
                ("--amount", &case.amount),
                ("--mint", &case.mint),
                ("--label", &case.label),
            ] {
                if let Some(value) = value {
                    flags.extend([flag, value.as_str()]);
                }
            }
            let args = parse(&flags);
            let address = RingAddress {
                recipient: ShieldedAddress::from_bytes(&recipient).unwrap(),
                ring_program_id: case.ring_program_id.parse().unwrap(),
                pairing: args.pairing().unwrap().unwrap(),
            };
            assert_eq!(args.request(address).to_string(), case.uri, "{}", case.name);
        }
    }

    #[test]
    fn address_issues_in_order_and_refuses_an_index_past_the_gap() {
        let mut state = AnonymousRingState::new(Address::new_from_array([4; 32]), 0);
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
            Some(ClientError::TooManyIssuedAddresses { .. })
        ));
        assert!(try_parse(&["--beyond-gap"]).is_err());
    }

    #[test]
    fn a_reprinted_address_keeps_its_pairing_and_refuses_another() {
        let mut state = AnonymousRingState::new(Address::new_from_array([4; 32]), 0);
        let pairing = |state: &AnonymousRingState| state.issued()[0].pairing.clone();
        parse(&["--pairing", "any:5"]).issue(&mut state).unwrap();
        let rows = vec![PairingRow {
            mint: PairingRow::ANY.mint,
            min_amount: 5,
        }];
        let issued = Pairing::new(rows).unwrap();
        assert_eq!(pairing(&state), issued);
        parse(&["--index", "0"]).issue(&mut state).unwrap();
        parse(&["--index", "0", "--pairing", "any:5"])
            .issue(&mut state)
            .unwrap();
        assert_eq!(pairing(&state), issued);
        let refused = parse(&["--index", "0", "--no-pairing"])
            .issue(&mut state)
            .unwrap_err();
        assert!(refused.to_string().contains("another pairing"), "{refused}");
        assert_eq!(pairing(&state), issued);
    }

    #[test]
    fn pairing_rows_refuse_sol_more_than_four_rows_and_mixing_with_no_pairing() {
        for sol in ["sol:5", "SOL:5", "11111111111111111111111111111111:5"] {
            let refused = sol.parse::<PairingRowArg>().unwrap_err();
            assert!(refused.contains("any:<min>"), "{refused}");
        }
        assert!("any".parse::<PairingRowArg>().is_err());
        assert!("any:many".parse::<PairingRowArg>().is_err());
        let mint = Address::new_from_array([9; 32]);
        assert_eq!(
            format!("{mint}:7").parse::<PairingRowArg>().unwrap(),
            PairingRowArg(PairingRow {
                mint,
                min_amount: 7
            })
        );
        let five: Vec<&str> = ["--pairing", "any:1"].repeat(5);
        assert!(matches!(
            parse(&five)
                .pairing()
                .unwrap_err()
                .downcast_ref::<KeypairError>(),
            Some(KeypairError::InvalidRingAddressPairing(5))
        ));
        assert!(try_parse(&["--pairing", "any:1", "--no-pairing"]).is_err());
    }
}
