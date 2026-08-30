use std::{io::Read, str::FromStr};

use anyhow::{bail, Context, Result};
use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_address::Address;
use solana_pubkey::Pubkey;
use swap_prover::TAKE_MODE_DERIVED;
use swap_sdk::{
    instructions::{
        cancel::{Cancel, CancelProofInputParams},
        make::{Make, MakeProofInputParams, OrderMarker, SppTxHashes},
        take::{Take, TakeProofInputParams},
    },
    prover::SwapProverClient,
    state::{OrderTerms, OrderUtxo, PlainTextData},
    MarkerData, ORDER_AUTHORITY_PDA_SEED,
};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_keypair::{constants::BLINDING_LEN, ShieldedAddress};
use zolana_transaction::{
    instructions::transact::SppProofOutputUtxo,
    serialization::confidential::ConfidentialOutputPlaintext,
};

const MAKE_INPUTS: u8 = 2;
const MAKE_OUTPUTS: u8 = 2;
const TAKE_INPUTS: u8 = 2;
const TAKE_OUTPUTS: u8 = 2;
const CANCEL_INPUTS: u8 = 1;
const CANCEL_OUTPUTS: u8 = 1;

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
    input_commitment: String,
    change_blinding: String,
    change_amount: String,
    order: OrderContext,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveMakeRequest {
    transact: String,
    private_tx_hash: String,
    external_data_hash: String,
    context: MakeContext,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OrderContext {
    tree: String,
    order_commitment: String,
    maker_pubkey: String,
    maker_address: String,
    taker_address: String,
    source_asset: AssetJson,
    source_amount: String,
    destination_asset: AssetJson,
    destination_amount: String,
    expiry_unix_ts: String,
    take_mode: String,
    order_blinding: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodeOrderRequest {
    tree: String,
    output_hash: String,
    plaintext: String,
    marker_data: String,
    maker_address: String,
    taker_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TakePlanRequest {
    payer: String,
    wallet_input_commitment: String,
    wallet_input_blinding: String,
    expires_at_ms: String,
    prover_profile_id: String,
    order: OrderContext,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TakeContext {
    payer: String,
    wallet_input_commitment: String,
    wallet_input_blinding: String,
    source_output_blinding: String,
    order: OrderContext,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveTakeRequest {
    transact: String,
    private_tx_hash: String,
    external_data_hash: String,
    context: TakeContext,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelPlanRequest {
    payer: String,
    expires_at_ms: String,
    prover_profile_id: String,
    order: OrderContext,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CancelContext {
    payer: String,
    source_output_blinding: String,
    order: OrderContext,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveCancelRequest {
    transact: String,
    private_tx_hash: String,
    external_data_hash: String,
    context: CancelContext,
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
        "decode-order" => decode_order(serde_json::from_str(&input)?)?,
        "take-plan" => take_plan(serde_json::from_str(&input)?)?,
        "prove-take" => prove_take(serde_json::from_str(&input)?)?,
        "cancel-plan" => cancel_plan(serde_json::from_str(&input)?)?,
        "prove-cancel" => prove_cancel(serde_json::from_str(&input)?)?,
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
        "shape": { "inputs": MAKE_INPUTS, "outputs": MAKE_OUTPUTS },
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
        input_commitment: plan["inputs"][0]["commitment"]
            .as_str()
            .context("commitment")?
            .to_owned(),
        change_blinding: encode_hex(&change.blinding),
        change_amount: change.amount.to_string(),
        order: OrderContext {
            tree: plan["input_tree"].as_str().context("tree")?.to_owned(),
            order_commitment: encode_hex(&order_hash),
            maker_pubkey: payer.to_string(),
            maker_address: request.maker_address,
            taker_address: request.taker_address,
            source_asset: request.source_asset,
            source_amount: source_amount.to_string(),
            destination_asset: request.destination_asset,
            destination_amount: destination_amount.to_string(),
            expiry_unix_ts: expiry_unix_ts.to_string(),
            take_mode: TAKE_MODE_DERIVED.to_string(),
            order_blinding: encode_hex(&order.blinding),
        },
    };
    Ok(json!({ "plan": plan, "context": context }))
}

fn prove_make(request: ProveMakeRequest) -> Result<Value> {
    let context = request.context;
    let maker = ShieldedAddress::from_str(&context.order.maker_address)?;
    let payer = Pubkey::from_str(&context.payer)?;
    if maker.solana_address()?.to_bytes() != payer.to_bytes() {
        bail!("maker address is not owned by payer");
    }
    let order = order_from_context(&context.order)?;
    check_order_commitment(&order, &context.order)?;
    let change = SppProofOutputUtxo {
        asset: context.order.source_asset.mint()?,
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
        tree: Pubkey::from_str(&context.order.tree)?,
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
        "instruction": instruction_json(instruction)
    }))
}

fn decode_order(request: DecodeOrderRequest) -> Result<Value> {
    let marker = MarkerData::try_from_slice(&decode_hex(&request.marker_data)?)
        .context("invalid order marker")?;
    let output_hash: [u8; 32] = decode_array(&request.output_hash)?;
    if marker.order_utxo_hash != output_hash {
        bail!("marker does not name this output");
    }
    let maker = ShieldedAddress::from_str(&request.maker_address)
        .context("invalid maker shielded address")?;
    if maker.solana_address()?.to_bytes() != marker.maker_pubkey {
        bail!("resolved maker address does not match marker owner");
    }
    let taker = ShieldedAddress::from_str(&request.taker_address)
        .context("invalid taker shielded address")?;
    let plaintext = ConfidentialOutputPlaintext::deserialize(&decode_hex(&request.plaintext)?)
        .context("invalid confidential order plaintext")?;
    if plaintext.ring_program_id.is_some() {
        bail!("swap order output is not in the default ring");
    }
    let order_data = PlainTextData::deserialize(
        plaintext
            .data
            .utxo_data()
            .context("order plaintext has no utxo data")?,
    )?;
    if order_data.taker != taker.solana_address()? {
        bail!("order is assigned to a different taker");
    }
    if order_data.take_mode != TAKE_MODE_DERIVED {
        bail!("unsupported order take mode");
    }
    let source_asset = asset_from_id(plaintext.asset_id)?;
    let destination_asset = asset_from_id(order_data.destination_asset_id)?;
    let order = OrderUtxo {
        terms: OrderTerms {
            destination_mint: destination_asset.mint()?,
            destination_amount: order_data.destination_amount,
            destination: maker,
            taker: order_data.taker,
            expiry: order_data.expiry,
            take_mode: order_data.take_mode,
        },
        blinding: plaintext.blinding,
        source_mint: source_asset.mint()?,
        source_amount: plaintext.amount,
        destination_asset_id: order_data.destination_asset_id,
    };
    let reconstructed = order.output_utxo(taker.viewing_pubkey)?.hash()?;
    if reconstructed != output_hash {
        bail!("reconstructed order does not match its on-chain commitment");
    }
    let context = OrderContext {
        tree: request.tree,
        order_commitment: request.output_hash,
        maker_pubkey: Pubkey::new_from_array(marker.maker_pubkey).to_string(),
        maker_address: request.maker_address,
        taker_address: request.taker_address,
        source_asset,
        source_amount: plaintext.amount.to_string(),
        destination_asset,
        destination_amount: order_data.destination_amount.to_string(),
        expiry_unix_ts: order_data.expiry.to_string(),
        take_mode: order_data.take_mode.to_string(),
        order_blinding: encode_hex(&plaintext.blinding),
    };
    Ok(json!({ "order": context }))
}

fn take_plan(request: TakePlanRequest) -> Result<Value> {
    let payer = Address::from_str(&request.payer).context("invalid payer")?;
    let order = order_from_context(&request.order)?;
    check_order_commitment(&order, &request.order)?;
    let taker = ShieldedAddress::from_str(&request.order.taker_address)?;
    if taker.solana_address()? != payer || order.terms.taker != payer {
        bail!("order is assigned to a different taker");
    }
    let taker_in = SppProofOutputUtxo {
        asset: order.terms.destination_mint,
        amount: order.terms.destination_amount,
        blinding: decode_array(&request.wallet_input_blinding)?,
        owner_address: Some(taker),
        owner_tag: Some(taker.signing_pubkey.confidential_view_tag()?),
        ..Default::default()
    };
    if taker_in.hash()? != decode_array(&request.wallet_input_commitment)? {
        bail!("wallet input opening does not match its commitment");
    }
    let source_output = order.source_output(taker, zolana_keypair::random_blinding());
    let destination_output = order.derived_destination_output(order.terms.destination)?;
    let authority = order_authority()?;
    let plan = json!({
        "program_id": swap_program::ID.to_string(),
        "input_tree": request.order.tree,
        "shape": { "inputs": TAKE_INPUTS, "outputs": TAKE_OUTPUTS },
        "inputs": [
            program_order_input(&order, &request.order, &authority)?,
            { "type": "Wallet", "commitment": request.wallet_input_commitment },
        ],
        "program_authorities": [{ "seeds": authority }],
        "outputs": [
            output_json(&source_output, &request.order.source_asset)?,
            output_json(&destination_output, &request.order.destination_asset)?,
        ],
        "messages": [],
        "public_effects": { "type": "PrivateOnly" },
        "prover_profile_id": request.prover_profile_id,
        "expires_at_ms": request.expires_at_ms,
    });
    let context = TakeContext {
        payer: request.payer,
        wallet_input_commitment: request.wallet_input_commitment,
        wallet_input_blinding: request.wallet_input_blinding,
        source_output_blinding: encode_hex(&source_output.blinding),
        order: request.order,
    };
    Ok(json!({ "plan": plan, "context": context }))
}

fn prove_take(request: ProveTakeRequest) -> Result<Value> {
    let context = request.context;
    let payer = Pubkey::from_str(&context.payer)?;
    let order = order_from_context(&context.order)?;
    check_order_commitment(&order, &context.order)?;
    let taker = ShieldedAddress::from_str(&context.order.taker_address)?;
    if taker.solana_address()?.to_bytes() != payer.to_bytes()
        || order.terms.taker.to_bytes() != payer.to_bytes()
    {
        bail!("order is assigned to a different taker");
    }
    let taker_in = SppProofOutputUtxo {
        asset: order.terms.destination_mint,
        amount: order.terms.destination_amount,
        blinding: decode_array(&context.wallet_input_blinding)?,
        owner_address: Some(taker),
        owner_tag: Some(taker.signing_pubkey.confidential_view_tag()?),
        ..Default::default()
    };
    if taker_in.hash()? != decode_array(&context.wallet_input_commitment)? {
        bail!("wallet input opening does not match its commitment");
    }
    let source_output = order.source_output(taker, decode_array(&context.source_output_blinding)?);
    let destination_output = order.derived_destination_output(order.terms.destination)?;
    let expected_private_tx_hash: [u8; 32] = decode_array(&request.private_tx_hash)?;
    let proof_inputs = TakeProofInputParams {
        order_utxo: order,
        taker_in,
        source_output,
        destination_output,
        external_data_hash: decode_array(&request.external_data_hash)?,
    }
    .to_proof_inputs()?;
    if proof_inputs.private_tx_hash != expected_private_tx_hash {
        bail!("take context does not match prepared private_tx_hash");
    }
    let proof = SwapProverClient::new().prove_take(&proof_inputs)?;
    let transact = decode_transact(&request.transact, &expected_private_tx_hash)?;
    let instruction = Take {
        payer,
        tree: Pubkey::from_str(&context.order.tree)?,
        take_proof: proof.into(),
        spp_proof: transact,
    }
    .instruction()?;
    check_private_tx_binding(&instruction.data, &expected_private_tx_hash)?;
    Ok(json!({ "instruction": instruction_json(instruction) }))
}

fn cancel_plan(request: CancelPlanRequest) -> Result<Value> {
    let payer = Address::from_str(&request.payer).context("invalid payer")?;
    let order = order_from_context(&request.order)?;
    check_order_commitment(&order, &request.order)?;
    if order.terms.destination.solana_address()? != payer
        || Address::from_str(&request.order.maker_pubkey)? != payer
    {
        bail!("order maker does not match payer");
    }
    let source_output =
        order.source_output(order.terms.destination, zolana_keypair::random_blinding());
    let authority = order_authority()?;
    let plan = json!({
        "program_id": swap_program::ID.to_string(),
        "input_tree": request.order.tree,
        "shape": { "inputs": CANCEL_INPUTS, "outputs": CANCEL_OUTPUTS },
        "inputs": [program_order_input(&order, &request.order, &authority)?],
        "program_authorities": [{ "seeds": authority }],
        "outputs": [output_json(&source_output, &request.order.source_asset)?],
        "messages": [],
        "public_effects": { "type": "PrivateOnly" },
        "prover_profile_id": request.prover_profile_id,
        "expires_at_ms": request.expires_at_ms,
    });
    let context = CancelContext {
        payer: request.payer,
        source_output_blinding: encode_hex(&source_output.blinding),
        order: request.order,
    };
    Ok(json!({ "plan": plan, "context": context }))
}

fn prove_cancel(request: ProveCancelRequest) -> Result<Value> {
    let context = request.context;
    let payer = Pubkey::from_str(&context.payer)?;
    let maker = Pubkey::from_str(&context.order.maker_pubkey)?;
    if payer != maker {
        bail!("order maker does not match payer");
    }
    let order = order_from_context(&context.order)?;
    check_order_commitment(&order, &context.order)?;
    if order.terms.destination.solana_address()?.to_bytes() != maker.to_bytes() {
        bail!("maker shielded address does not match payer");
    }
    let taker = ShieldedAddress::from_str(&context.order.taker_address)?;
    let source_output = order.source_output(
        order.terms.destination,
        decode_array(&context.source_output_blinding)?,
    );
    let expected_private_tx_hash: [u8; 32] = decode_array(&request.private_tx_hash)?;
    let proof_inputs = CancelProofInputParams {
        order_utxo: order.clone(),
        taker_viewing_pubkey: taker.viewing_pubkey,
        source_output,
        external_data_hash: decode_array(&request.external_data_hash)?,
    }
    .to_proof_inputs()?;
    if proof_inputs.private_tx_hash != expected_private_tx_hash {
        bail!("cancel context does not match prepared private_tx_hash");
    }
    let proof = SwapProverClient::new().prove_cancel(&proof_inputs)?;
    let transact = decode_transact(&request.transact, &expected_private_tx_hash)?;
    let instruction = Cancel {
        maker,
        payer,
        tree: Pubkey::from_str(&context.order.tree)?,
        cancel_proof: proof.into(),
        order_expiry: order.terms.expiry,
        spp_proof: transact,
    }
    .instruction()?;
    check_private_tx_binding(&instruction.data, &expected_private_tx_hash)?;
    Ok(json!({ "instruction": instruction_json(instruction) }))
}

fn order_from_context(context: &OrderContext) -> Result<OrderUtxo> {
    let maker = ShieldedAddress::from_str(&context.maker_address)?;
    let taker = ShieldedAddress::from_str(&context.taker_address)?;
    let maker_pubkey = Address::from_str(&context.maker_pubkey)?;
    if maker.solana_address()? != maker_pubkey {
        bail!("maker shielded address does not match marker owner");
    }
    let take_mode = parse_u64("take_mode", &context.take_mode)?;
    if take_mode != TAKE_MODE_DERIVED {
        bail!("unsupported order take mode");
    }
    Ok(OrderUtxo {
        terms: OrderTerms {
            destination_mint: context.destination_asset.mint()?,
            destination_amount: parse_u64("destination_amount", &context.destination_amount)?,
            destination: maker,
            taker: taker.solana_address()?,
            expiry: parse_u64("expiry_unix_ts", &context.expiry_unix_ts)?,
            take_mode,
        },
        blinding: decode_array(&context.order_blinding)?,
        source_mint: context.source_asset.mint()?,
        source_amount: parse_u64("source_amount", &context.source_amount)?,
        destination_asset_id: context.destination_asset.asset_id()?,
    })
}

fn check_order_commitment(order: &OrderUtxo, context: &OrderContext) -> Result<()> {
    let taker = ShieldedAddress::from_str(&context.taker_address)?;
    if order.output_utxo(taker.viewing_pubkey)?.hash()? != decode_array(&context.order_commitment)?
    {
        bail!("order context does not match its commitment");
    }
    if order.to_input_utxo()?.hash()? != decode_array(&context.order_commitment)? {
        bail!("order output and program spend commitments differ");
    }
    Ok(())
}

fn asset_from_id(asset_id: u64) -> Result<AssetJson> {
    if asset_id == zolana_transaction::SOL_ASSET_ID {
        Ok(AssetJson::Sol)
    } else {
        bail!("this demo currently discovers SOL swap orders only")
    }
}

fn order_authority() -> Result<Vec<String>> {
    let (_, bump) = Pubkey::find_program_address(&[ORDER_AUTHORITY_PDA_SEED], &swap_program::ID);
    Ok(vec![
        encode_hex(ORDER_AUTHORITY_PDA_SEED),
        encode_hex(&[bump]),
    ])
}

fn program_order_input(
    order: &OrderUtxo,
    context: &OrderContext,
    authority: &[String],
) -> Result<Value> {
    Ok(json!({
        "type": "Program",
        "commitment": context.order_commitment,
        "authority_seeds": authority,
        "asset": context.source_asset,
        "amount": context.source_amount,
        "blinding": context.order_blinding,
        "data_hash": encode_hex(&order.terms.data_hash()?),
        "nullifier_secret": encode_hex(&[0u8; BLINDING_LEN]),
    }))
}

fn output_json(output: &SppProofOutputUtxo, asset: &AssetJson) -> Result<Value> {
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
}

fn decode_transact(encoded: &str, expected_hash: &[u8; 32]) -> Result<TransactIxData> {
    let transact: TransactIxData = wincode::deserialize_exact(&decode_hex(encoded)?)?;
    if transact.private_tx_hash != *expected_hash {
        bail!("prepared transact private_tx_hash mismatch");
    }
    Ok(transact)
}

fn check_private_tx_binding(data: &[u8], private_tx_hash: &[u8; 32]) -> Result<()> {
    if data
        .windows(private_tx_hash.len())
        .filter(|window| *window == private_tx_hash)
        .count()
        != 1
    {
        bail!("outer instruction has an ambiguous private_tx_hash binding");
    }
    Ok(())
}

fn instruction_json(instruction: solana_instruction::Instruction) -> InstructionJson {
    InstructionJson {
        program_id: instruction.program_id.to_string(),
        accounts: instruction
            .accounts
            .into_iter()
            .map(|account| InstructionAccountJson {
                address: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            })
            .collect(),
        data: encode_hex(&instruction.data),
    }
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
    if !value.len().is_multiple_of(2) {
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

    #[test]
    fn decode_order_reconstructs_the_make_commitment() {
        let made = make_plan(request()).expect("make plan");
        let context: MakeContext =
            serde_json::from_value(made["context"].clone()).expect("make context");
        let order = order_from_context(&context.order).expect("order");
        let taker = ShieldedAddress::from_str(TAKER).expect("taker");
        let output = order.output_utxo(taker.viewing_pubkey).expect("output");
        let plaintext = ConfidentialOutputPlaintext {
            asset_id: context.order.source_asset.asset_id().expect("asset"),
            amount: output.amount,
            blinding: output.blinding,
            ring_program_id: None,
            data: output.data,
        }
        .serialize()
        .expect("plaintext");
        let marker = borsh::to_vec(&MarkerData {
            order_utxo_hash: decode_array(&context.order.order_commitment).expect("hash"),
            maker_pubkey: Pubkey::from_str(PAYER).expect("payer").to_bytes(),
        })
        .expect("marker");
        let decoded = decode_order(DecodeOrderRequest {
            tree: context.order.tree.clone(),
            output_hash: context.order.order_commitment.clone(),
            plaintext: encode_hex(&plaintext),
            marker_data: encode_hex(&marker),
            maker_address: MAKER.to_owned(),
            taker_address: TAKER.to_owned(),
        })
        .expect("decode order");
        assert_eq!(
            decoded["order"]["order_commitment"],
            context.order.order_commitment
        );
        assert_eq!(decoded["order"]["maker_pubkey"], PAYER);
    }

    #[test]
    fn take_plan_spends_program_order_before_exact_wallet_note() {
        let made = make_plan(request()).expect("make plan");
        let context: MakeContext =
            serde_json::from_value(made["context"].clone()).expect("make context");
        let taker = ShieldedAddress::from_str(TAKER).expect("taker");
        let wallet_input = SppProofOutputUtxo {
            asset: zolana_transaction::SOL_MINT,
            amount: 1_000_000,
            blinding: [7u8; 32],
            owner_address: Some(taker),
            owner_tag: Some(taker.signing_pubkey.confidential_view_tag().expect("tag")),
            ..Default::default()
        };
        let plan = take_plan(TakePlanRequest {
            payer: taker.solana_address().expect("payer").to_string(),
            wallet_input_commitment: encode_hex(&wallet_input.hash().expect("hash")),
            wallet_input_blinding: encode_hex(&wallet_input.blinding),
            expires_at_ms: "2000000000000".to_owned(),
            prover_profile_id: "zolnet-devnet-external-http-v1".to_owned(),
            order: context.order,
        })
        .expect("take plan");
        assert_eq!(plan["plan"]["shape"], json!({ "inputs": 2, "outputs": 2 }));
        assert_eq!(plan["plan"]["inputs"][0]["type"], "Program");
        assert_eq!(plan["plan"]["inputs"][1]["type"], "Wallet");
    }

    #[test]
    fn cancel_plan_is_a_program_only_refund() {
        let made = make_plan(request()).expect("make plan");
        let context: MakeContext =
            serde_json::from_value(made["context"].clone()).expect("make context");
        let plan = cancel_plan(CancelPlanRequest {
            payer: PAYER.to_owned(),
            expires_at_ms: "2000000000000".to_owned(),
            prover_profile_id: "zolnet-devnet-external-http-v1".to_owned(),
            order: context.order,
        })
        .expect("cancel plan");
        assert_eq!(plan["plan"]["shape"], json!({ "inputs": 1, "outputs": 1 }));
        assert_eq!(plan["plan"]["inputs"][0]["type"], "Program");
        assert_eq!(plan["plan"]["outputs"][0]["amount"], "2000000");
    }
}
