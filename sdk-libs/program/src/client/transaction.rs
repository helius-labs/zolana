use solana_address::Address;
use zolana_circuit::{Input, ArrayVec, ShieldedAddress, UtxoOwner, from_bytes, to_bytes};
use zolana_circuit::protocol::{CheckedTransaction, TxContext, Utxo, UtxoMeta};
use zolana_keypair::{Curve, ShieldedAddress as NativeShieldedAddress};
use zolana_transaction::{Mint, SppProofOutputUtxo, WalletUtxo, utxo::{ProofInputUtxo, SppProofInputUtxo}};
use zolana_transaction::instructions::transact::{ConfidentialTransaction, FinalizedTransaction, canonical_shape};

#[derive(Debug)]
pub struct ClientError(String);
impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for ClientError {}
pub(crate) fn fail(error: impl core::fmt::Display) -> ClientError { ClientError(error.to_string()) }

/// Native records needed to resolve the UTXOs, assets, and viewing addresses
/// that a circuit's checked transaction commits to.
#[derive(Default)]
pub struct InputRecords {
    inputs: Vec<WalletUtxo>,
    addresses: Vec<NativeShieldedAddress>,
    mints: Vec<Mint>,
}

impl InputRecords {
    pub fn new() -> Self { Self::default() }

    pub fn address(&mut self, address: &NativeShieldedAddress) -> Result<ShieldedAddress, ClientError> {
        let tag = match address.signing_pubkey.curve().map_err(fail)? {
            Curve::Ed25519 | Curve::Pda => zolana_hasher::primitives::SOLANA_OWNER_TAG,
        };
        let key = address.signing_pubkey.confidential_view_tag().map_err(fail)?;
        let owner = UtxoOwner::from_preimage(tag, &key, &address.nullifier_pubkey).map_err(fail)?;
        let value = ShieldedAddress::new(owner, *address.viewing_pubkey.as_bytes());
        if !self.addresses.contains(address) { self.addresses.push(*address); }
        Ok(value)
    }

    pub fn asset(&mut self, mint: Mint) -> [u8; 32] {
        if !self.mints.contains(&mint) { self.mints.push(mint); }
        *mint.asset.as_array()
    }

    pub fn utxo(&mut self, wallet: &WalletUtxo) -> Result<Utxo, ClientError> {
        let spp = SppProofInputUtxo::from(wallet);
        if spp.is_dummy() { return Ok(Utxo::dummy()); }
        let fields = ProofInputUtxo::try_from(&spp).map_err(fail)?;
        let key = wallet.utxo.owner.confidential_view_tag().map_err(fail)?;
        let owner = UtxoOwner::from_preimage(zolana_hasher::primitives::SOLANA_OWNER_TAG, &key, &wallet.nullifier_pubkey).map_err(fail)?;
        let field = |bytes: &[u8; 32]| from_bytes(bytes).map_err(fail);
        let value = Utxo {
            domain: zolana_interface::UTXO_DOMAIN, owner,
            asset: self.asset(wallet.utxo.asset),
            amount: wallet.utxo.amount,
            blinding: field(&fields.blinding)?, data_hash: field(&fields.data_hash)?,
            ring_data_hash: field(&fields.ring_data_hash)?, ring_program_id: field(&fields.ring_program_id)?,
            tree_id: wallet.tree_id,
            meta: UtxoMeta { nullifier: field(&wallet.nullifier)?, latest_tree_id: wallet.latest_tree_id.unwrap_or(0), has_latest_tree_id: wallet.latest_tree_id.is_some() },
        };
        if to_bytes(&value.hash().map_err(fail)?) != wallet.utxo_hash {
            return Err(fail("the input commitment does not match its preimage"));
        }
        self.inputs.push(wallet.clone());
        Ok(value)
    }

    pub fn utxos<const N: usize>(&mut self, wallets: &[WalletUtxo]) -> Result<ArrayVec<Utxo, N>, ClientError> {
        let values = wallets.iter().map(|wallet| self.utxo(wallet)).collect::<Result<Vec<_>, _>>()?;
        ArrayVec::new(values).map_err(fail)
    }

    pub fn context(seed: &[u8; 32], output_tree: Option<u16>) -> Result<TxContext, ClientError> {
        Ok(TxContext { blinding_seed: from_bytes(seed).map_err(fail)?, output_tree_id: output_tree.unwrap_or(0), uses_output_tree_id: output_tree.is_some() })
    }

    fn owner(&self, owner: &UtxoOwner, sender: &NativeShieldedAddress) -> Result<NativeShieldedAddress, ClientError> {
        let hash = to_bytes(&owner.hash().map_err(fail)?);
        let mut matches = self.addresses.iter().filter(|address| address.owner_hash().is_ok_and(|h| h == hash));
        match (matches.next(), matches.next()) {
            (Some(address), None) => Ok(*address),
            (Some(_), Some(_)) => Err(fail("the output owner has ambiguous viewing addresses")),
            (None, _) if sender.owner_hash().map_err(fail)? == hash => Ok(*sender),
            _ => Err(fail("the output owner has no viewing address")),
        }
    }

    fn mint(&self, address: &[u8; 32]) -> Result<Mint, ClientError> {
        let bytes = *address;
        if bytes == [0; 32] { return Ok(Mint::SOL); }
        self.mints.iter().find(|mint| mint.asset.as_array() == &bytes).copied().ok_or_else(|| fail("the asset has no registry record"))
    }

    pub fn finalize(&self, checked: &CheckedTransaction, sender: &NativeShieldedAddress, payer: Address) -> Result<FinalizedTransaction, ClientError> {
        let tree = checked.output_tree_id;
        let padding_tree = self.inputs.first().map(|input| input.tree_id);
        let mut inputs = Vec::new();
        for hash in checked.inputs.iter().skip(checked.addresses.len()) {
            let hash = to_bytes(hash);
            if hash == [0; 32] {
                if checked.preserve_input_slots { inputs.push(WalletUtxo::dummy(padding_tree.ok_or_else(|| fail("no input tree"))?).map_err(fail)?); }
            } else {
                inputs.push(self.inputs.iter().find(|input| input.utxo_hash == hash).cloned().ok_or_else(|| fail("the spent input is not recorded"))?);
            }
        }
        let mut addresses = Vec::new();
        for created in &checked.addresses {
            let owner = self.owner(&created.owner, sender)?;
            let input = SppProofInputUtxo::new_address(owner.signing_pubkey, to_bytes(&created.seed), zolana_instruction::ADDRESS_TREE_ID).map_err(fail)?;
            if input.nullifier != to_bytes(&created.address) { return Err(fail("address reservation mismatch")); }
            addresses.push(input);
        }
        let shape = canonical_shape(inputs.len() + addresses.len(), checked.outputs.len()).map_err(fail)?;
        let tx = if checked.preserve_input_slots { ConfidentialTransaction::new_with_addresses(inputs, addresses, payer) }
                 else { ConfidentialTransaction::new_compact_with_addresses(inputs, addresses, payer) };
        let mut tx = tx.and_then(|tx| tx.with_blinding_seed(to_bytes(&checked.blinding_seed)))
            .and_then(|tx| tx.with_output_tree_id(tree)).map_err(fail)?;
        for item in &checked.outputs {
            if item.empty { tx.add_empty_output_utxo().map_err(fail)?; }
            else {
                let output = &item.output;
                let amount = output.amount;
                let mut utxo = SppProofOutputUtxo::new(self.mint(&output.asset)?, amount, self.owner(&output.owner, sender)?).map_err(fail)?;
                let hash = to_bytes(&output.data_hash);
                if let Some(data) = &output.data { utxo = utxo.with_utxo_data(data.clone(), hash); }
                else if hash != [0; 32] { utxo.data_hash = Some(hash); }
                tx.add_output_utxo(utxo).map_err(fail)?;
            }
        }
        for transfer in &checked.public_transfers {
            use zolana_transaction::instructions::transact::SettlementTarget;
            let mint = self.mint(&transfer.asset)?;
            let account = Address::new_from_array(transfer.account);
            let target = if mint == Mint::SOL { SettlementTarget::Sol { user_sol_account: account } }
                         else { SettlementTarget::Spl { user_spl_token: account } };
            let amount = transfer.amount;
            tx.settle(mint, transfer.is_deposit, amount, target).map_err(fail)?;
        }
        tx.pad_utxos_with_empty_outputs(shape, sender).map_err(fail)?;
        let finalized = tx.finalize(sender).map_err(fail)?;
        let actual_hash = finalized.padding_independent_private_tx_hash().map_err(fail)?;
        if actual_hash != to_bytes(checked.private_tx_hash()) { return Err(fail("the finalized transaction differs from the circuit commitment")); }
        let transfers = finalized.interface_transfers().iter().copied().map(interface_transfer).collect::<Vec<_>>();
        let actual_transaction = zolana_instruction::transaction_hash(&actual_hash, &transfers).map_err(fail)?;
        if actual_transaction != to_bytes(checked.transaction_hash()) { return Err(fail("the finalized public transfers differ from the circuit commitment")); }
        let hashes = finalized.output_hashes().map_err(fail)?;
        for (index, item) in checked.outputs.iter().enumerate() {
            let expected = if item.empty && finalized.output_utxos()[index].is_compact() { [0; 32] } else { to_bytes(&item.hash) };
            if hashes[index] != expected { return Err(fail("the finalized output differs from the circuit commitment")); }
        }
        Ok(finalized)
    }
}

fn interface_transfer(transfer: zolana_transaction::instructions::transact::SettlementTransfer) -> zolana_instruction::PublicTransfer {
    use zolana_transaction::instructions::transact::SettlementTransfer;
    match transfer {
        SettlementTransfer::Sol { is_deposit, amount, user_sol_account } => zolana_instruction::PublicTransfer { mint: zolana_transaction::SOL_MINT, is_deposit, amount, account: user_sol_account },
        SettlementTransfer::Spl { mint, is_deposit, amount, user_spl_token } => zolana_instruction::PublicTransfer { mint, is_deposit, amount, account: user_spl_token },
    }
}

#[derive(Clone)]
pub struct ProgramProofInputs {
    fields: Vec<(String, zolana_circuit::xark::prover::Fr)>,
    json: serde_json::Value,
}
impl ProgramProofInputs {
    pub fn new<P: Input>(program: &P, public_hash: zolana_circuit::Field) -> Self {
        let mut fields = zolana_circuit::xark::input::leaves(program, "program");
        fields.push(("public_hash".into(), public_hash.into()));
        let json = serde_json::json!({
            "program": zolana_circuit::xark::client::to_json(program).expect("Input encodes its own values"),
            "public_hash": public_hash.to_decimal(),
        });
        Self { fields, json }
    }

    pub fn to_json(&self) -> serde_json::Value {
        self.json.clone()
    }
}
impl zolana_circuit::xark::prover::ProveInputs for ProgramProofInputs {
    fn into_inputs(self) -> Vec<(String, zolana_circuit::xark::prover::Fr)> { self.fields }
}

pub struct ProgramTransaction {
    pub finalized: FinalizedTransaction,
    pub proof_inputs: ProgramProofInputs,
    pub public_hash: [u8; 32],
}

impl InputRecords {
    pub fn create_program_transaction<P: Input>(&self, program: &P, checked: CheckedTransaction,
        sender: &NativeShieldedAddress, payer: Address) -> Result<ProgramTransaction, ClientError>
    {
        let finalized = self.finalize(&checked, sender, payer)?;
        let proof_inputs = ProgramProofInputs::new(program, *checked.public_hash());
        Ok(ProgramTransaction { finalized, proof_inputs, public_hash: to_bytes(checked.public_hash()) })
    }
}
