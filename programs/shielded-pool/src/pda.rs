//! Minimal PDA derivation helper. Mirrors `Pubkey::create_program_address`
//! using `sol_sha256` directly so we don't need `pinocchio-pubkey` (which
//! would force a pinocchio 0.11 bump).
//!
//! Only the off-curve hash is computed — we assume the caller already knows
//! the bump, so the curve check `sol_create_program_address` does for us is
//! unnecessary. If `bump` is wrong, the derived address simply won't match
//! the signer the caller passed in, and we reject the call.

use pinocchio::Address;

/// `b"ProgramDerivedAddress"`.
const PDA_MARKER: &[u8; 21] = b"ProgramDerivedAddress";

/// Derive a PDA address from a single byte-string seed, a bump, and a program
/// id. Caller is responsible for using a bump that yields an off-curve point;
/// this helper just hashes the inputs.
pub fn derive_pda(seed: &[u8], bump: u8, program_id: &[u8; 32]) -> Address {
    let mut out = [0u8; 32];

    #[cfg(target_os = "solana")]
    {
        use pinocchio::syscalls::sol_sha256;

        // sol_sha256 wants an array of (ptr, len) pairs as a flat *const u8.
        // We hand-roll the layout: seed | [bump] | program_id | PDA_MARKER.
        #[repr(C)]
        struct Slice {
            ptr: *const u8,
            len: u64,
        }
        let bump_arr = [bump];
        let parts: [Slice; 4] = [
            Slice { ptr: seed.as_ptr(), len: seed.len() as u64 },
            Slice { ptr: bump_arr.as_ptr(), len: 1 },
            Slice { ptr: program_id.as_ptr(), len: 32 },
            Slice { ptr: PDA_MARKER.as_ptr(), len: PDA_MARKER.len() as u64 },
        ];
        unsafe {
            sol_sha256(parts.as_ptr() as *const u8, 4, out.as_mut_ptr());
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        // Host fallback so unit tests on the host can call us. Uses the
        // `sha2` crate via `light-hasher`'s transitive dep is overkill — we
        // pull `sha2` directly when the crate is built off-target.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update([bump]);
        hasher.update(program_id);
        hasher.update(PDA_MARKER);
        let digest = hasher.finalize();
        out.copy_from_slice(&digest);
    }

    Address::from(out)
}
