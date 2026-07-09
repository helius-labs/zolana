//! Per-wallet, cross-process note reservations backed by a lock directory.
//!
//! Concurrent `wallet transfer` invocations for the same wallet must pick
//! distinct notes, or they build proofs against the same input and one loses the
//! race on-chain. Each candidate note is claimed by atomically creating a
//! lockfile named by its commitment hash under `<wallet>.inflight/` with
//! `O_CREAT | O_EXCL`; the create fails if another live process already holds it.
//! A lockfile older than [`RESERVATION_TTL`] is treated as stale (a crashed
//! process) and reclaimed. The lockfile is removed when the [`Reservation`] is
//! dropped.

use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::{bail, Result};
use zolana_client::SpendableUtxo;

/// A live reservation is reclaimable after this long, so a crashed process cannot
/// wedge a note forever.
pub(super) const RESERVATION_TTL: Duration = Duration::from_secs(10 * 60);

/// An atomically claimed note. Dropping it releases the lockfile.
pub(super) struct Reservation {
    lockfile: PathBuf,
    pub(super) hash: [u8; 32],
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // Best effort: a leftover lockfile is reclaimed by the TTL sweep anyway.
        let _ = fs::remove_file(&self.lockfile);
    }
}

impl Reservation {
    /// Refresh the lockfile's mtime so a long proof or indexer wait does not make
    /// a live reservation look stale to another process.
    pub(super) fn refresh(&self) -> Result<()> {
        let mut file = OpenOptions::new().append(true).open(&self.lockfile)?;
        file.write_all(b".")?;
        Ok(())
    }
}

pub(super) fn refresh_all(reservations: &[Reservation]) -> Result<()> {
    for reservation in reservations {
        reservation.refresh()?;
    }
    Ok(())
}

fn lockfile_name(hash: &[u8; 32]) -> String {
    hex::encode(hash)
}

/// A lockfile is stale (reclaimable) once its age reaches the TTL, or if its age
/// cannot be determined (clock skew / missing mtime is treated as stale rather
/// than wedging the note forever).
fn is_stale(modified: SystemTime, now: SystemTime, ttl: Duration) -> bool {
    match now.duration_since(modified) {
        Ok(age) => age >= ttl,
        Err(_) => true,
    }
}

/// True if `path` names a live (non-stale) lockfile. A file whose mtime is older
/// than the TTL is stale and is removed so it can be reclaimed.
fn is_live_lock(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        // No mtime: reclaim rather than wedge the note.
        let _ = fs::remove_file(path);
        return false;
    };
    if is_stale(modified, SystemTime::now(), RESERVATION_TTL) {
        // Reclaim it. Racing with another reclaimer is fine: we then fail the
        // O_EXCL create below and move on.
        let _ = fs::remove_file(path);
        return false;
    }
    true
}

/// Atomically claim `hash`'s lockfile in `dir`. Returns `Ok(true)` on a fresh
/// claim, `Ok(false)` if another live process holds it.
fn try_claim(dir: &Path, hash: &[u8; 32]) -> Result<bool> {
    let path = dir.join(lockfile_name(hash));
    if is_live_lock(&path) {
        return Ok(false);
    }
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Try to reserve one exact note hash. Returns `Ok(None)` if another live
/// process already holds it.
pub(super) fn reserve_hash(dir: &Path, hash: [u8; 32]) -> Result<Option<Reservation>> {
    fs::create_dir_all(dir)?;
    if try_claim(dir, &hash)? {
        Ok(Some(Reservation {
            lockfile: dir.join(lockfile_name(&hash)),
            hash,
        }))
    } else {
        Ok(None)
    }
}

/// Reserve every explicit hash or fail if any is currently held elsewhere.
pub(super) fn reserve_hashes(dir: &Path, hashes: &[[u8; 32]]) -> Result<Vec<Reservation>> {
    let mut reservations = Vec::with_capacity(hashes.len());
    let mut seen = HashSet::with_capacity(hashes.len());
    for hash in hashes {
        if !seen.insert(*hash) {
            bail!("duplicate input note {}", hex::encode(hash));
        }
        match reserve_hash(dir, *hash)? {
            Some(reservation) => reservations.push(reservation),
            None => bail!(
                "input note {} is reserved by another process",
                hex::encode(hash)
            ),
        }
    }
    Ok(reservations)
}

/// Reserve the first unreserved note in `candidates` that on its own covers
/// `amount`. `candidates` should be the wallet's unspent notes in selection
/// order (spent notes are already excluded by the caller). Returns `Ok(None)`
/// when no single unreserved note covers `amount`.
///
/// This claims a single note; a caller needing several distinct notes calls it
/// repeatedly (each successful [`Reservation`] holds its lock until dropped).
pub(super) fn reserve_covering(
    dir: &Path,
    candidates: &[SpendableUtxo],
    amount: u64,
) -> Result<Option<Reservation>> {
    fs::create_dir_all(dir)?;
    for note in candidates {
        if note.amount < amount {
            continue;
        }
        if let Some(reservation) = reserve_hash(dir, note.hash)? {
            return Ok(Some(reservation));
        }
    }
    Ok(None)
}

/// The `.inflight` lock directory for a wallet, derived from its resolved keypair
/// path: `<dir>/<stem>.inflight/` (e.g. `wallets/alice.json` ->
/// `wallets/alice.inflight/`).
pub(super) fn inflight_dir(keypair_path: &Path) -> Option<PathBuf> {
    let parent = keypair_path.parent()?;
    let stem = keypair_path.file_stem()?.to_str()?;
    Some(parent.join(format!("{stem}.inflight")))
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{note, temp_dir};
    use super::*;

    #[test]
    fn concurrent_reservations_claim_distinct_notes() {
        let dir = temp_dir("zolana-inflight", "distinct");
        let notes = vec![note(100, 1), note(100, 2), note(100, 3)];

        // Three "concurrent" reservations must pick three distinct hashes, held
        // simultaneously (none dropped between claims).
        let first = reserve_covering(&dir, &notes, 50).unwrap().expect("first");
        let second = reserve_covering(&dir, &notes, 50).unwrap().expect("second");
        let third = reserve_covering(&dir, &notes, 50).unwrap().expect("third");

        let mut hashes = [first.hash, second.hash, third.hash];
        hashes.sort();
        assert_eq!(hashes, [[1u8; 32], [2u8; 32], [3u8; 32]]);

        // A fourth reservation finds every note locked.
        assert!(reserve_covering(&dir, &notes, 50).unwrap().is_none());

        drop((first, second, third));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn releasing_a_reservation_frees_the_note() {
        let dir = temp_dir("zolana-inflight", "release");
        let notes = vec![note(100, 7)];
        {
            let held = reserve_covering(&dir, &notes, 10).unwrap().expect("held");
            assert_eq!(held.hash, [7u8; 32]);
            // While held, the only note is unavailable.
            assert!(reserve_covering(&dir, &notes, 10).unwrap().is_none());
        }
        // After drop, it is claimable again.
        let reclaimed = reserve_covering(&dir, &notes, 10)
            .unwrap()
            .expect("reclaimed");
        assert_eq!(reclaimed.hash, [7u8; 32]);
        drop(reclaimed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn skips_notes_that_do_not_cover_amount() {
        let dir = temp_dir("zolana-inflight", "cover");
        let notes = vec![note(10, 1), note(20, 2), note(100, 3)];
        let reservation = reserve_covering(&dir, &notes, 50)
            .unwrap()
            .expect("covering note");
        // First note covering 50 is the 100-note (hash tag 3).
        assert_eq!(reservation.hash, [3u8; 32]);
        drop(reservation);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reserve_hashes_rejects_duplicates() {
        let dir = temp_dir("zolana-inflight", "duplicates");
        let err = match reserve_hashes(&dir, &[[8u8; 32], [8u8; 32]]) {
            Ok(_) => panic!("duplicate hash must error"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("duplicate input note"),
            "unexpected error: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reserve_hashes_respects_live_locks() {
        let dir = temp_dir("zolana-inflight", "explicit-held");
        let held = reserve_hash(&dir, [9u8; 32])
            .unwrap()
            .expect("initial claim");
        let err = match reserve_hashes(&dir, &[[9u8; 32]]) {
            Ok(_) => panic!("held hash must error"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("reserved by another process"),
            "unexpected error: {err}"
        );
        drop(held);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_classifies_stale_and_live_lockfiles() {
        let now = SystemTime::now();
        // A fresh lockfile (just created) is live.
        assert!(!is_stale(now, now, RESERVATION_TTL));
        // A lockfile older than the TTL is stale and reclaimable.
        let old = now - (RESERVATION_TTL + Duration::from_secs(5));
        assert!(is_stale(old, now, RESERVATION_TTL));
        // A future mtime (clock skew) is treated as stale, never wedging a note.
        let future = now + Duration::from_secs(30);
        assert!(is_stale(future, now, RESERVATION_TTL));
    }

    #[test]
    fn inflight_dir_is_sibling_of_wallet_file() {
        let dir = inflight_dir(Path::new("/home/x/.config/zolana/wallets/alice.json"))
            .expect("inflight dir");
        assert_eq!(
            dir,
            PathBuf::from("/home/x/.config/zolana/wallets/alice.inflight")
        );
    }
}
