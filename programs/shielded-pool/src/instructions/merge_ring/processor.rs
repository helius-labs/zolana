use crate::instructions::shared::caused_by;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_hasher::primitives::{hash_bytes, solana_owner_identity};
use spr_interface::{
    error::ShieldedPoolError, instruction::instruction_data::merge_ring::MergeRingIxDataRef,
};

use super::account::MergeRingAccounts;
use crate::instructions::{
    merge::{
        cache::load_merge_cache,
        processor::{process_merge_core, validate_field_elements, MergeCoreAccounts},
        verify::MergeOwnerBinding,
    },
    shared::{check_field_element, check_not_expired},
};

/// Policy-ring analog of `merge_transact`, invoked via CPI from a ring program.
/// The ring's `ring_config` account signs (authorization), and SPP does not
/// check `protocol_config.merge_authorities`. A merge under a zero nullifier key
/// needs the owner's signature.
#[inline(never)]
pub fn process_merge_ring_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ix = MergeRingIxDataRef::from_bytes(data)
        .map_err(caused_by(ShieldedPoolError::InvalidMergeShape))?;
    let merge = &ix.merge;
    validate_field_elements(merge)?;
    check_field_element(
        ix.output_ring_data_hash,
        "output ring data hash",
        None,
        ShieldedPoolError::NonCanonicalRingDataHash,
    )?;
    if !merge.output_encryption.is_canonical() {
        return Err(ShieldedPoolError::NonCanonicalMergeCiphertext.into());
    }
    let clock = Clock::get()?;
    check_not_expired(merge.expiry_unix_ts, &clock)?;

    let merge_accounts = MergeRingAccounts::validate_and_parse(
        accounts,
        merge.nullifiers.len(),
        merge.cache_slot,
        ix.authority,
    )?;
    let cache = load_merge_cache(merge_accounts.cache, clock.unix_timestamp)?;

    // A policy ring has no `user_record` registry, so the `Ring` binding takes
    // the program id from the signing `ring_config` and the owner from the
    // signer, never from instruction data.
    let published_owner = published_owner(merge_accounts.owner.map(AccountView::address))?;
    let output_view_tag = match merge_accounts.owner {
        Some(_) => published_owner,
        None => *merge
            .nullifiers
            .first()
            .ok_or(ShieldedPoolError::InvalidMergeShape)?,
    };
    let owner_binding = MergeOwnerBinding::Ring {
        ring_program_id: hash_bytes(merge_accounts.ring_program_id.as_array())?,
        output_ring_data_hash: *ix.output_ring_data_hash,
        published_owner,
        output_encryption: merge.output_encryption,
    };

    // The indexer republishes the output `ring_data_hash` from this
    // instruction's data as the output payload so the wallet can reconstruct the
    // ring output.
    process_merge_core(
        MergeCoreAccounts {
            input_tree: merge_accounts.input_tree,
            output_tree: merge_accounts.output_tree,
            payer: merge_accounts.payer,
            nullifier_pdas: merge_accounts.nullifier_pdas,
        },
        merge,
        owner_binding,
        cache,
        output_view_tag,
        clock.slot,
    )
}

/// The signer's identity enters the statement, so a proof publishing any other
/// owner fails the pairing.
pub(crate) fn published_owner(owner: Option<&Address>) -> Result<[u8; 32], ProgramError> {
    owner.map_or(Ok([0; 32]), |owner| {
        Ok(solana_owner_identity(owner.as_array())?)
    })
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use spr_interface::{
        instruction::instruction_data::merge_transact::MergeTransactIxDataRef, tree_slot::TreeSlot,
    };

    use super::*;
    use crate::instructions::merge::verify::{
        tests::{derived, field, ix_data, output_encryption},
        MergeProof,
    };

    #[test]
    fn only_the_signer_reproduces_the_zero_key_statement() {
        let vector: Value =
            serde_json::from_str(include_str!("../../../../../test-vectors/merge_ring.json"))
                .expect("vector");
        let statement = &vector["statement"];
        let encryption = output_encryption(
            &vector["output_ciphertext_salt"],
            &vector["output_ciphertext"],
        );
        let nullifiers: Vec<[u8; 32]> = statement["nullifiers"]
            .as_array()
            .expect("nullifiers")
            .iter()
            .map(field)
            .collect();
        let data = ix_data(
            &nullifiers,
            field(&statement["output_hash"]),
            field(&statement["private_tx_hash"]),
            encryption,
        );
        let ix = MergeTransactIxDataRef::from_bytes(&data).expect("parse");
        let tree_id = |key: &str| statement[key].as_u64().expect("tree id") as u16;
        let statement_hash = |signer: Option<&Address>| {
            MergeProof::new(
                &ix,
                derived(
                    TreeSlot::new(
                        tree_id("tree_id"),
                        field(&statement["utxo_root"]),
                        field(&statement["nullifier_root"]),
                    ),
                    tree_id("output_tree_id"),
                    field(&statement["external_data_hash"]),
                    MergeOwnerBinding::Ring {
                        ring_program_id: field(&statement["ring_program_hash"]),
                        output_ring_data_hash: field(&statement["output_ring_data_hash"]),
                        published_owner: published_owner(signer).expect("owner identity"),
                        output_encryption: encryption,
                    },
                ),
            )
            .public_input_hash()
            .expect("hash")
        };

        assert_eq!(
            statement_hash(None),
            field(&statement["nonzero_key_public_input_hash"])
        );
        let owner = Address::new_from_array(field(&vector["owner_pubkey"]));
        let zero_key = field(&statement["zero_key_public_input_hash"]);
        assert_eq!(statement_hash(Some(&owner)), zero_key);
        assert_ne!(
            statement_hash(Some(&Address::new_from_array([0x2b; 32]))),
            zero_key
        );
    }
}
