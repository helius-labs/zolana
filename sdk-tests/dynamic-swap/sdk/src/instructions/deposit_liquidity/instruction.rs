use anyhow::Result;
use dynamic_swap_program::instructions::shared::u64_right_align;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_interface::instruction::{
    builders::{AssetDeposit, Deposit, DepositAsset, DepositSplAccounts},
    UtxoData,
};
use zolana_keypair::PublicKey;
use zolana_transaction::utxo::Blinding;

use crate::{
    err,
    state::{encode_pool_note, pool_authority_owner_hash},
    tag,
};

/// Shields a public `amount` of the destination asset from the depositor's SPL
/// token account into a new pool note (`booked = amount`, fully public, no
/// proof) by forwarding an SPP proofless deposit through the swap program,
/// which validates the entry and raises `liquidity_bound`. Permissionless: the
/// depositor signs its own SPL transfer.
pub struct DepositLiquidity {
    pub depositor: Pubkey,
    pub pair: Pubkey,
    pub tree: Pubkey,
    pub mint: Pubkey,
    pub user_token: Pubkey,
    pub token_program: Pubkey,
    pub amount: u64,
    /// Fresh CSPRNG blinding, published in the clear (the whole deposit note
    /// is public); see `DepositEntry::blinding`.
    pub blinding: Blinding,
}

impl DepositLiquidity {
    pub fn instruction(self) -> Result<Instruction> {
        let pool_owner_hash = pool_authority_owner_hash(&self.pair)?;
        // The pool authority's standard confidential view tag, so the maker's
        // pool-note scan finds deposits without extra state.
        let pool_pda = crate::pool_authority_pda(&self.pair);
        let view_tag = PublicKey::from_pda(&pool_pda)
            .confidential_view_tag()
            .map_err(err)?;

        // Reuse the interface deposit builder for the SPP account layout and
        // entry shaping, then wrap it under the swap program with the pair
        // account prepended and the swap tag in front of the verbatim
        // `DepositIxData` bytes.
        let spp_ix = Deposit {
            tree: self.tree,
            depositor: self.depositor,
            deposits: vec![AssetDeposit {
                asset: DepositAsset::Spl(DepositSplAccounts {
                    mint: self.mint,
                    user_token: self.user_token,
                    token_program: self.token_program,
                }),
                view_tag,
                owner: pool_owner_hash,
                blinding: self.blinding,
                amount: self.amount,
                utxo_data: Some(UtxoData {
                    data_hash: u64_right_align(self.amount),
                    data: encode_pool_note(self.amount),
                }),
                memo: None,
            }],
        }
        .instruction()
        .map_err(err)?;

        let mut instruction_data = vec![tag::DEPOSIT_LIQUIDITY];
        instruction_data.extend_from_slice(spp_ix.data.get(1..).unwrap_or_default());

        let mut accounts = vec![AccountMeta::new(self.pair, false)];
        accounts.extend(spp_ix.accounts);

        Ok(Instruction {
            program_id: dynamic_swap_program::ID,
            accounts,
            data: instruction_data,
        })
    }
}
