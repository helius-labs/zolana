use std::{io::Read, str::FromStr};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_address::Address;
use solana_pubkey::Pubkey;
use swap_prover::TAKE_MODE_DERIVED;
use swap_sdk::{
    instructions::make::{Make, MakeProofInputParams, OrderMarker, SppTxHashes},
    prover::SwapProverClient,
    state::{OrderTerms, OrderUtxo},
    ORDER_AUTHORITY_PDA_SEED,
};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::instructions::transact::SppProofOutputUtxo;

const SHAPE_INPUTS: u8 = 2;
const SHAPE_OUTPUTS: u8 = 2;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum AssetJson {
    Sol,
    Spl { mint: String, asset_id: String },
}

impl AssetJson {
    fn mint(&self) -> Result<Address> {
        match self {
            Self::Sol => Ok(zolana_transaction::SOL_MINT),
            Self::Spl { mint, .. } => Address::from_str(mint).context("invalid SPL mint"),
        }
    }

    fn asset_id(&self) -> Result<u64> {
        match self {
            Self::Sol => Ok(zolana_transaction::SOL_ASSET_ID),
            Self::Spl { asset_id, .. } => asset_id.parse().context("invalid SPL asset id"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MakePlanRequest {
    payer: String,
    maker_address: String,
    taker_address: String,
    input_tree: String,
    input_commitment: String,
    input_amount: String,
    source_asset: AssetJson,
    source_amount: String,
    destination_asset: AssetJson,
    destination_amount: String,
    expires_at_ms: String,
    prover_profile_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MakeContext {
    payer: String,
    tree: String,
    input_commitment: String,
    source_asset: AssetJson,
    source_amount: String,
    destination_asset: AssetJson,
    destination_amount: String,
    maker_address: String,
    taker_address: String,
    expiry_unix_ts: String,
    order_blinding: String,
    change_blinding: String,
    change_amount: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveMakeRequest {
    transact: String,
    private_tx_hash: String,
    external_data_hash: String,
    context: MakeContext,
}

#[derive(Debug, Serialize)]
struct InstructionAccountJson {
    address: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Debug, Serialize)]
struct InstructionJson {
    program_id: String,
    accounts: Vec<InstructionAccountJson>,
    data: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let output = match command.as_str() {
        "make-plan" => make_plan(serde_json::from_str(&input)?)?,
        "prove-make" => prove_make(serde_json::from_str(&input)?)?,
        _ => bail!("unknown command {command:?}"),
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn make_plan(request: MakePlanRequest) -> Result<Value> {
    let payer = Address::from_str(&request.payer).context("invalid payer")?;
    let maker = ShieldedAddress::from_str(&request.maker_address)
        .context("invalid maker shielded address")?;
    let taker = ShieldedAddress::from_str(&request.taker_address)
        .context("invalid taker shielded address")?;
    if maker.solana_address()? != payer {
        bail!("maker address is not owned by payer");
    }
    let input_amount = parse_u64("input_amount", &request.input_amount)?;
    let source_amount = parse_u64("source_amount", &request.source_amount)?;
    let destination_amount = parse_u64("destination_amount", &request.destination_amount)?;
    let expires_at_ms = parse_u64("expires_at_ms", &request.expires_at_ms)?;
    if source_amount == 0 || destination_amount == 0 || source_amount > input_amount {
        bail!("invalid swap amounts");
    }
    let source_mint = request.source_asset.mint()?;
    let destination_mint = request.destination_asset.mint()?;
    let expiry_unix_ts = expires_at_ms.div_ceil(1_000);
    let terms = OrderTerms {
        destination_mint,
        destination_amount,
        destination: maker,
        taker: taker.solana_address()?,
        expiry: expiry_unix_ts,
        take_mode: TAKE_MODE_DERIVED,
    };
    let order = OrderUtxo {
        terms,
        blinding: zolana_keypair::random_blinding(),
        source_mint,
        source_amount,
        destination_asset_id: request.destination_asset.asset_id()?,
    };
    let order_output = order.output_utxo(taker.viewing_pubkey)?;
    let change = SppProofOutputUtxo::new(source_mint, input_amount - source_amount, maker)?;
    let order_hash = order_output.hash()?;
    let marker = OrderMarker {
        order_utxo_hash: order_hash,
        maker_pubkey: Pubkey::new_from_array(payer.to_bytes()),
        taker_address: taker,
    }
    .message()?;
    let (_, order_authority_bump) =
        Pubkey::find_program_address(&[ORDER_AUTHORITY_PDA_SEED], &swap_program::ID);

    let output_json = |output: &SppProofOutputUtxo, asset: &AssetJson| -> Result<Value> {
        let recipient = output.owner_address.context("missing output owner")?;
        Ok(json!({
            "recipient": recipient.to_string(),
            "asset": asset,
            "amount": output.amount.to_string(),
            "blinding": encode_hex(&output.blinding),
            "data": encode_hex(output.data.utxo_data().unwrap_or_default()),
            "data_hash": output.data_hash.map(|value| encode_hex(&value)),
            "memo": encode_hex(output.data.memo().unwrap_or_default()),
        }))
    };
    let plan = json!({
        "program_id": swap_program::ID.to_string(),
        "input_tree": request.input_tree,
        "shape": { "inputs": SHAPE_INPUTS, "outputs": SHAPE_OUTPUTS },
        "inputs": [{ "type": "Wallet", "commitment": request.input_commitment }],
        "program_authorities": [{
            "seeds": [
                encode_hex(ORDER_AUTHORITY_PDA_SEED),
                encode_hex(&[order_authority_bump]),
            ],
        }],
        "outputs": [
            output_json(&change, &request.source_asset)?,
            output_json(&order_output, &request.source_asset)?,
        ],
        "messages": [{
            "view_tag": encode_hex(&marker.view_tag),
            "data": encode_hex(&marker.data),
        }],
        "public_effects": { "type": "PrivateOnly" },
        "prover_profile_id": request.prover_profile_id,
        "expires_at_ms": request.expires_at_ms,
    });
    let context = MakeContext {
        payer: request.payer,
        tree: plan["input_tree"].as_str().context("tree")?.to_owned(),
        input_commitment: plan["inputs"][0]["commitment"]
            .as_str()
            .context("commitment")?
            .to_owned(),
        source_asset: request.source_asset,
        source_amount: source_amount.to_string(),
        destination_asset: request.destination_asset,
        destination_amount: destination_amount.to_string(),
        maker_address: request.maker_address,
        taker_address: request.taker_address,
        expiry_unix_ts: expiry_unix_ts.to_string(),
        order_blinding: encode_hex(&order.blinding),
        change_blinding: encode_hex(&change.blinding),
        change_amount: change.amount.to_string(),
    };
    Ok(json!({ "plan": plan, "context": context }))
}

fn prove_make(request: ProveMakeRequest) -> Result<Value> {
    let context = request.context;
    let maker = ShieldedAddress::from_str(&context.maker_address)?;
    let taker = ShieldedAddress::from_str(&context.taker_address)?;
    let payer = Pubkey::from_str(&context.payer)?;
    if maker.solana_address()?.to_bytes() != payer.to_bytes() {
        bail!("maker address is not owned by payer");
    }
    let order = OrderUtxo {
        terms: OrderTerms {
            destination_mint: context.destination_asset.mint()?,
            destination_amount: parse_u64("destination_amount", &context.destination_amount)?,
            destination: maker,
            taker: taker.solana_address()?,
            expiry: parse_u64("expiry_unix_ts", &context.expiry_unix_ts)?,
            take_mode: TAKE_MODE_DERIVED,
        },
        blinding: decode_array(&context.order_blinding)?,
        source_mint: context.source_asset.mint()?,
        source_amount: parse_u64("source_amount", &context.source_amount)?,
        destination_asset_id: context.destination_asset.asset_id()?,
    };
    let change = SppProofOutputUtxo {
        asset: context.source_asset.mint()?,
        amount: parse_u64("change_amount", &context.change_amount)?,
        blinding: decode_array(&context.change_blinding)?,
        owner_address: Some(maker),
        owner_tag: Some(maker.signing_pubkey.confidential_view_tag()?),
        ..Default::default()
    };
    let expected_private_tx_hash: [u8; 32] = decode_array(&request.private_tx_hash)?;
    let proof_inputs = MakeProofInputParams {
        order_utxo: order,
        change,
        spp_tx_hashes: SppTxHashes {
            source_input_hash: decode_array(&context.input_commitment)?,
            external_data_hash: decode_array(&request.external_data_hash)?,
        },
    }
    .to_proof_inputs()?;
    if proof_inputs.private_tx_hash != expected_private_tx_hash {
        bail!("make context does not match prepared private_tx_hash");
    }
    let proof = SwapProverClient::new().prove_make(&proof_inputs)?;
    let transact_bytes = decode_hex(&request.transact)?;
    let transact: TransactIxData = wincode::deserialize_exact(&transact_bytes)?;
    if transact.private_tx_hash != expected_private_tx_hash {
        bail!("prepared transact private_tx_hash mismatch");
    }
    let instruction = Make {
        payer,
        tree: Pubkey::from_str(&context.tree)?,
        make_proof: proof.into(),
        spp_proof: transact,
    }
    .instruction()?;
    if instruction
        .data
        .windows(expected_private_tx_hash.len())
        .filter(|window| *window == expected_private_tx_hash)
        .count()
        != 1
    {
        bail!("outer instruction has an ambiguous private_tx_hash binding");
    }
    Ok(json!({
        "instruction": InstructionJson {
            program_id: instruction.program_id.to_string(),
            accounts: instruction.accounts.into_iter().map(|account| InstructionAccountJson {
                address: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }).collect(),
            data: encode_hex(&instruction.data),
        }
    }))
}

fn parse_u64(label: &str, value: &str) -> Result<u64> {
    value.parse().with_context(|| format!("invalid {label}"))
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    decode_hex(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected {N} bytes"))
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        bail!("invalid hex length");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).context("invalid hex"))
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAKER: &str = "nXCAmMVUZp1ZmFhfCNEzqubevSpVL99efGHhs67HUAoZz9N586mg7z3dJC8yA5GrQWaryp1aLvUb1QCfD7an7BgndNmGsxELB3ekLcUND29g1bsvqJdBLpvoGJ8nN3oY3UWRVd";
    const TAKER: &str = "voLjBXYEkm7ANBA2Rfz7vdBfMhYbu3Desx2KNHPYLqTtvhaBYgzsZjCwKM1TRNPL1jX53bGwRoauu9U1xFqb9QhvDwi13fnTzPSeXkSM1HEPxjPXexe9irZA7r7DVocXkXJ3TK";
    const PAYER: &str = "AFRUJXNTGMZQo59gGetRNBSZwK9vBUCZMdJXgSac9kKd";

    fn request() -> MakePlanRequest {
        MakePlanRequest {
            payer: PAYER.to_owned(),
            maker_address: MAKER.to_owned(),
            taker_address: TAKER.to_owned(),
            input_tree: "11111111111111111111111111111111".to_owned(),
            input_commitment: "11".repeat(32),
            input_amount: "3000000".to_owned(),
            source_asset: AssetJson::Sol,
            source_amount: "2000000".to_owned(),
            destination_asset: AssetJson::Sol,
            destination_amount: "1000000".to_owned(),
            expires_at_ms: "2000000000000".to_owned(),
            prover_profile_id: "zolnet-devnet-external-http-v1".to_owned(),
        }
    }

    #[test]
    fn make_plan_is_tvc_spp_shape_and_program_bound() {
        let output = make_plan(request()).expect("make plan");
        let plan = &output["plan"];
        assert_eq!(plan["program_id"], swap_program::ID.to_string());
        assert_eq!(plan["shape"], json!({ "inputs": 2, "outputs": 2 }));
        assert_eq!(plan["inputs"][0]["commitment"], "11".repeat(32));
        assert_eq!(
            plan["program_authorities"][0]["seeds"][0],
            "6f726465725f617574686f72697479"
        );
        assert_eq!(plan["outputs"][0]["amount"], "1000000");
        assert_eq!(plan["outputs"][1]["amount"], "2000000");
        assert_eq!(plan["messages"][0]["data"].as_str().unwrap().len(), 128);
        assert_eq!(output["context"]["payer"], PAYER);
    }

    #[test]
    fn make_plan_rejects_a_maker_not_owned_by_the_payer() {
        let mut request = request();
        request.payer = "11111111111111111111111111111111".to_owned();
        assert!(make_plan(request).is_err());
    }
}
