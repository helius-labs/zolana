//! Delegated ring-scope readers: the on-chain records the ring RPC accepts in
//! place of the authority's own signature.

use anyhow::{Context, Result};
use custom_ring_program::state::ReaderRecord;
use custom_ring_sdk::{reader_record_pda, GrantReader, RevokeReader};
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{Rpc, SolanaRpc};

use crate::init::read_pod;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderOutcome {
    Granted,
    AlreadyGranted,
    Revoked,
    NotGranted,
}

/// Idempotent: a second grant of the same key changes nothing.
pub fn grant(rpc: &SolanaRpc, authority: &dyn Signer, reader: Address) -> Result<ReaderOutcome> {
    if read_record(rpc, reader)?.is_some() {
        return Ok(ReaderOutcome::AlreadyGranted);
    }
    let ix = GrantReader {
        payer: authority.pubkey(),
        authority: authority.pubkey(),
        reader,
    }
    .instruction();
    rpc.create_and_send_transaction(&[ix], authority.pubkey(), &[authority])
        .context("grant_reader failed")?;
    Ok(ReaderOutcome::Granted)
}

/// Idempotent: revoking a key without a record changes nothing. The rent goes
/// back to the authority.
pub fn revoke(rpc: &SolanaRpc, authority: &dyn Signer, reader: Address) -> Result<ReaderOutcome> {
    if read_record(rpc, reader)?.is_none() {
        return Ok(ReaderOutcome::NotGranted);
    }
    let ix = RevokeReader {
        authority: authority.pubkey(),
        reader,
        rent_recipient: authority.pubkey(),
    }
    .instruction();
    rpc.create_and_send_transaction(&[ix], authority.pubkey(), &[authority])
        .context("revoke_reader failed")?;
    Ok(ReaderOutcome::Revoked)
}

pub fn read_record<R: Rpc>(rpc: &R, reader: Address) -> Result<Option<ReaderRecord>> {
    read_pod(rpc, reader_record_pda(&reader), "reader record")
}
