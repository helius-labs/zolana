use solana_address::Address;
use spr_circuit::protocol::{CheckedTransaction, TxContext, Utxo, UtxoMeta};
use spr_circuit::{from_bytes, to_bytes, ArrayVec, Input, ShieldedAddress, UtxoOwner};
use spr_keypair::{Curve, ShieldedAddress as NativeShieldedAddress};
use spr_transaction::instructions::transact::{
    canonical_shape, ConfidentialTransaction, FinalizedTransaction,
};
use spr_transaction::{
    utxo::{ProofInputUtxo, SppProofInputUtxo},
    Mint, SppProofOutputUtxo, WalletUtxo,
};

#[derive(Debug)]
pub enum ClientError {
    InvalidInput(String),
    /// The program's circuit logic rejected the inputs, e.g. a failed
    /// `require`.
    Circuit(spr_circuit::CircuitError),
    DataHashMismatch,
    TooManyInputs {
        capacity: usize,
        found: usize,
    },
}
impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidInput(message) => f.write_str(message),
            Self::Circuit(error) => error.fmt(f),
            Self::DataHashMismatch => f.write_str("the utxo hash does not commit its data"),
            Self::TooManyInputs { capacity, found } => {
                write!(f, "the program accepts {capacity} inputs, received {found}")
            }
        }
    }
}
impl std::error::Error for ClientError {}
impl From<spr_circuit::CircuitError> for ClientError {
    fn from(error: spr_circuit::CircuitError) -> Self {
        Self::Circuit(error)
    }
}
#[doc(hidden)]
pub fn fail(error: impl core::fmt::Display) -> ClientError {
    ClientError::InvalidInput(error.to_string())
}

fn capacity_error(error: spr_circuit::CircuitError) -> ClientError {
    match error.kind() {
        spr_circuit::CircuitErrorKind::TooManyItems { capacity, found } => {
            ClientError::TooManyInputs {
                capacity: *capacity,
                found: *found,
            }
        }
        _ => fail(error),
    }
}

/// Client-selected output tree and optional reproducible transaction blinding.
#[derive(Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize),
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
#[cfg_attr(feature = "tsify", derive(tsify::Tsify))]
pub struct TransactionOptions {
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "spr_keypair::serde_helpers::bytes")
    )]
    #[cfg_attr(feature = "tsify", tsify(optional, type = "Uint8Array"))]
    pub blinding_seed: Option<[u8; 32]>,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "tsify", tsify(optional))]
    pub output_tree_id: Option<u16>,
}
impl TransactionOptions {
    pub fn into_context(self) -> Result<TxContext, ClientError> {
        let seed = self
            .blinding_seed
            .unwrap_or_else(spr_keypair::random_blinding);
        InputRecords::context(&seed, self.output_tree_id)
    }
}

/// Native records needed to resolve the UTXOs, assets, and viewing addresses
/// that a circuit's checked transaction commits to.
#[derive(Default)]
pub struct InputRecords {
    inputs: Vec<WalletUtxo>,
    addresses: Vec<NativeShieldedAddress>,
    mints: Vec<Mint>,
}

impl InputRecords {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn address(
        &mut self,
        address: &NativeShieldedAddress,
    ) -> Result<ShieldedAddress, ClientError> {
        let tag = match address.signing_pubkey.curve().map_err(fail)? {
            Curve::Ed25519 | Curve::Pda => spr_hasher::primitives::SOLANA_OWNER_TAG,
        };
        let key = address
            .signing_pubkey
            .confidential_view_tag()
            .map_err(fail)?;
        let owner = UtxoOwner::from_preimage(tag, &key, &address.nullifier_pubkey).map_err(fail)?;
        let value = ShieldedAddress::new(owner, *address.viewing_pubkey.as_bytes());
        if !self.addresses.contains(address) {
            self.addresses.push(*address);
        }
        Ok(value)
    }

    /// Records `mint` for the outputs of its asset. One asset has one asset ID:
    /// a second record of the same address with another ID is refused, since
    /// outputs would otherwise carry whichever ID was recorded first.
    pub fn asset(&mut self, mint: Mint) -> Result<[u8; 32], ClientError> {
        let recorded = if mint.asset == Mint::SOL.asset {
            Some(Mint::SOL)
        } else {
            self.mints
                .iter()
                .find(|known| known.asset == mint.asset)
                .copied()
        };
        match recorded {
            Some(known) if known != mint => {
                return Err(fail("the asset is recorded with a different asset id"))
            }
            Some(_) => {}
            None => self.mints.push(mint),
        }
        Ok(*mint.asset.as_array())
    }

    pub fn utxo(&mut self, wallet: &WalletUtxo) -> Result<Utxo, ClientError> {
        let spp = SppProofInputUtxo::from(wallet);
        if spp.is_dummy() {
            return Ok(Utxo::dummy());
        }
        let fields = ProofInputUtxo::try_from(&spp).map_err(fail)?;
        let key = wallet.utxo.owner.confidential_view_tag().map_err(fail)?;
        let owner = UtxoOwner::from_preimage(
            spr_hasher::primitives::SOLANA_OWNER_TAG,
            &key,
            &wallet.nullifier_pubkey,
        )
        .map_err(fail)?;
        let field = |bytes: &[u8; 32]| from_bytes(bytes).map_err(fail);
        let value = Utxo {
            domain: spr_interface::UTXO_DOMAIN,
            owner,
            asset: self.asset(wallet.utxo.asset)?,
            amount: wallet.utxo.amount,
            blinding: field(&fields.blinding)?,
            data_hash: field(&fields.data_hash)?,
            ring_data_hash: field(&fields.ring_data_hash)?,
            ring_program_id: field(&fields.ring_program_id)?,
            tree_id: wallet.tree_id,
            meta: UtxoMeta {
                nullifier: field(&wallet.nullifier)?,
                latest_tree_id: wallet.latest_tree_id.unwrap_or(0),
                has_latest_tree_id: wallet.latest_tree_id.is_some(),
            },
        };
        if to_bytes(&value.hash().map_err(fail)?) != wallet.utxo_hash {
            return Err(fail("the input commitment does not match its preimage"));
        }
        self.inputs.push(wallet.clone());
        Ok(value)
    }

    pub fn utxos<const N: usize>(
        &mut self,
        wallets: &[WalletUtxo],
    ) -> Result<ArrayVec<Utxo, N>, ClientError> {
        if wallets.len() > N {
            return Err(ClientError::TooManyInputs {
                capacity: N,
                found: wallets.len(),
            });
        }
        let values = wallets
            .iter()
            .map(|wallet| self.utxo(wallet))
            .collect::<Result<Vec<_>, _>>()?;
        ArrayVec::new(values).map_err(capacity_error)
    }

    pub fn bounded<T: spr_circuit::PaddedInput, const N: usize>(
        values: Vec<T>,
    ) -> Result<ArrayVec<T, N>, ClientError> {
        ArrayVec::new(values).map_err(capacity_error)
    }

    pub fn context(seed: &[u8; 32], output_tree: Option<u16>) -> Result<TxContext, ClientError> {
        Ok(TxContext {
            blinding_seed: from_bytes(seed).map_err(fail)?,
            output_tree_id: output_tree.unwrap_or(0),
            uses_output_tree_id: output_tree.is_some(),
        })
    }

    fn owner(
        &self,
        owner: &UtxoOwner,
        sender: &NativeShieldedAddress,
    ) -> Result<NativeShieldedAddress, ClientError> {
        let hash = to_bytes(&owner.hash().map_err(fail)?);
        let mut matches = self
            .addresses
            .iter()
            .filter(|address| address.owner_hash().is_ok_and(|h| h == hash));
        match (matches.next(), matches.next()) {
            (Some(address), None) => Ok(*address),
            (Some(_), Some(_)) => Err(fail("the output owner has ambiguous viewing addresses")),
            (None, _) if sender.owner_hash().map_err(fail)? == hash => Ok(*sender),
            _ => Err(fail("the output owner has no viewing address")),
        }
    }

    fn mint(&self, address: &[u8; 32]) -> Result<Mint, ClientError> {
        let bytes = *address;
        if bytes == [0; 32] {
            return Ok(Mint::SOL);
        }
        self.mints
            .iter()
            .find(|mint| mint.asset.as_array() == &bytes)
            .copied()
            .ok_or_else(|| fail("the asset has no registry record"))
    }

    pub fn finalize(
        &self,
        checked: &CheckedTransaction,
        sender: &NativeShieldedAddress,
        payer: Address,
    ) -> Result<FinalizedTransaction, ClientError> {
        let tree = checked.output_tree_id;
        // Dummy slots sit in the tree of the first spent input, or in the
        // address tree when the transaction only creates addresses.
        let padding_tree = checked
            .inputs
            .iter()
            .find_map(|hash| {
                let hash = to_bytes(hash);
                self.inputs
                    .iter()
                    .find(|input| input.utxo_hash == hash)
                    .map(|input| input.tree_id)
            })
            .or_else(|| {
                checked
                    .addresses
                    .first()
                    .map(|_| spr_instruction::ADDRESS_TREE_ID)
            });
        let mut inputs = Vec::new();
        for hash in checked.inputs.iter().skip(checked.addresses.len()) {
            let hash = to_bytes(hash);
            if hash == [0; 32] {
                if checked.preserve_input_slots {
                    inputs.push(
                        WalletUtxo::dummy(padding_tree.ok_or_else(|| fail("no input tree"))?)
                            .map_err(fail)?,
                    );
                }
            } else {
                inputs.push(
                    self.inputs
                        .iter()
                        .find(|input| input.utxo_hash == hash)
                        .cloned()
                        .ok_or_else(|| fail("the spent input is not recorded"))?,
                );
            }
        }
        let mut addresses = Vec::new();
        for created in &checked.addresses {
            let owner = self.owner(&created.owner, sender)?;
            let input = SppProofInputUtxo::new_address(
                owner.signing_pubkey,
                to_bytes(&created.seed),
                spr_instruction::ADDRESS_TREE_ID,
            )
            .map_err(fail)?;
            if input.nullifier != to_bytes(&created.address) {
                return Err(fail("address reservation mismatch"));
            }
            addresses.push(input);
        }
        let shape =
            canonical_shape(inputs.len() + addresses.len(), checked.outputs.len()).map_err(fail)?;
        let tx = if checked.preserve_input_slots {
            ConfidentialTransaction::new_with_addresses(inputs, addresses, payer)
        } else {
            ConfidentialTransaction::new_compact_with_addresses(inputs, addresses, payer)
        };
        let mut tx = tx
            .and_then(|tx| tx.with_blinding_seed(to_bytes(&checked.blinding_seed)))
            .and_then(|tx| tx.with_output_tree_id(tree))
            .map_err(fail)?;
        for item in &checked.outputs {
            if item.empty {
                tx.add_empty_output_utxo().map_err(fail)?;
            } else {
                let output = &item.output;
                let amount = output.amount;
                let mut utxo = SppProofOutputUtxo::new(
                    self.mint(&output.asset)?,
                    amount,
                    self.owner(&output.owner, sender)?,
                )
                .map_err(fail)?;
                let hash = to_bytes(&output.data_hash);
                if let Some(data) = &output.data {
                    utxo = utxo.with_utxo_data(data.clone(), hash);
                } else if hash != [0; 32] {
                    utxo.data_hash = Some(hash);
                }
                tx.add_output_utxo(utxo).map_err(fail)?;
            }
        }
        for transfer in &checked.public_transfers {
            use spr_transaction::instructions::transact::SettlementTarget;
            let mint = self.mint(&transfer.asset)?;
            let account = Address::new_from_array(transfer.account);
            let target = if mint == Mint::SOL {
                SettlementTarget::Sol {
                    user_sol_account: account,
                }
            } else {
                SettlementTarget::Spl {
                    user_spl_token: account,
                }
            };
            let amount = transfer.amount;
            tx.settle(mint, transfer.is_deposit, amount, target)
                .map_err(fail)?;
        }
        tx.pad_utxos_with_empty_outputs(shape, sender)
            .map_err(fail)?;
        let finalized = tx.finalize(sender).map_err(fail)?;
        let actual_hash = finalized
            .padding_independent_private_tx_hash()
            .map_err(fail)?;
        if actual_hash != to_bytes(checked.private_tx_hash()) {
            return Err(fail(
                "the finalized transaction differs from the circuit commitment",
            ));
        }
        let transfers = finalized
            .interface_transfers()
            .iter()
            .copied()
            .map(interface_transfer)
            .collect::<Vec<_>>();
        let actual_transaction =
            spr_instruction::transaction_hash(&actual_hash, &transfers).map_err(fail)?;
        if actual_transaction != to_bytes(checked.transaction_hash()) {
            return Err(fail(
                "the finalized public transfers differ from the circuit commitment",
            ));
        }
        let hashes = finalized.output_hashes().map_err(fail)?;
        let outputs = finalized.output_utxos();
        // Padding only appends outputs, so every committed output has a slot.
        if hashes.len() != outputs.len() || outputs.len() < checked.outputs.len() {
            return Err(fail("the finalized transaction lacks a committed output"));
        }
        for ((item, output), hash) in checked.outputs.iter().zip(outputs).zip(&hashes) {
            let expected = if item.empty && output.is_compact() {
                [0; 32]
            } else {
                to_bytes(&item.hash)
            };
            if *hash != expected {
                return Err(fail(
                    "the finalized output differs from the circuit commitment",
                ));
            }
        }
        Ok(finalized)
    }
}

fn interface_transfer(
    transfer: spr_transaction::instructions::transact::SettlementTransfer,
) -> spr_instruction::PublicTransfer {
    use spr_transaction::instructions::transact::SettlementTransfer;
    match transfer {
        SettlementTransfer::Sol {
            is_deposit,
            amount,
            user_sol_account,
        } => spr_instruction::PublicTransfer {
            mint: spr_transaction::SOL_MINT,
            is_deposit,
            amount,
            account: user_sol_account,
        },
        SettlementTransfer::Spl {
            mint,
            is_deposit,
            amount,
            user_spl_token,
        } => spr_instruction::PublicTransfer {
            mint,
            is_deposit,
            amount,
            account: user_spl_token,
        },
    }
}

#[derive(Clone)]
pub struct ProgramProofInputs {
    fields: Vec<(String, spr_circuit::xark::prover::Fr)>,
}
impl ProgramProofInputs {
    pub fn new<P: Input>(program: &P, public_hash: spr_circuit::Field) -> Self {
        let mut fields = spr_circuit::xark::input::leaves(program, "program");
        fields.push(("public_hash".into(), public_hash.into()));
        Self { fields }
    }

    pub fn encoded(&self) -> std::collections::BTreeMap<String, String> {
        self.fields
            .iter()
            .map(|(name, value)| (name.clone(), value.to_string()))
            .collect()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self.encoded()).expect("field names and scalars serialize")
    }
}
impl spr_circuit::xark::prover::ProveInputs for ProgramProofInputs {
    fn into_inputs(self) -> Vec<(String, spr_circuit::xark::prover::Fr)> {
        self.fields
    }
}

pub struct ProgramTransaction {
    pub finalized: FinalizedTransaction,
    pub proof_inputs: ProgramProofInputs,
    pub public_hash: [u8; 32],
}

impl InputRecords {
    pub fn create_program_transaction<P: Input>(
        &self,
        program: &P,
        checked: CheckedTransaction,
        sender: &NativeShieldedAddress,
        payer: Address,
    ) -> Result<ProgramTransaction, ClientError> {
        let finalized = self.finalize(&checked, sender, payer)?;
        let proof_inputs = ProgramProofInputs::new(program, *checked.public_hash());
        Ok(ProgramTransaction {
            finalized,
            proof_inputs,
            public_hash: to_bytes(checked.public_hash()),
        })
    }
}
