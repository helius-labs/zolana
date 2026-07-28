//! Register agave BN254 batch syscalls into LiteSVM at agave prices.
//!
//! The arithmetic runs the `solana-bn254-batch-syscall` host path. Costs match
//! agave `program-runtime/src/execution_budget.rs` at pin 5134c411.

use litesvm::LiteSVM;
use solana_bn254_batch_syscall::{
    alt_bn128_g1_msm, alt_bn128_pairing_check, PodG1G2Pair, PodG1Point, PodPairingResult,
    PodScalar, Version, G1_BYTES, PAIR_BYTES, SCALAR_BYTES,
};
use solana_program_runtime::{
    invoke_context::InvokeContext,
    solana_sbpf::{
        declare_builtin_function,
        memory_region::{AccessType, MemoryMapping},
    },
};

// agave 5134c411 program-runtime/src/execution_budget.rs
const MSM_BASE_COST: u64 = 100;
const MSM_PER_POINT_COST: u64 = 3_322;
const PAIRING_BASE_COST: u64 = 17_246;
const PAIRING_PER_PAIR_COST: u64 = 5_741;
const G2_SUBGROUP_CHECK_COST: u64 = 3_595;
const MSM_DISCOUNT_PER_THOUSAND: [u64; 12] =
    [1000, 636, 449, 320, 246, 199, 166, 131, 113, 98, 85, 79];

pub fn msm_cost(num_points: u64) -> u64 {
    let discount = match num_points {
        0 => 1000,
        n => MSM_DISCOUNT_PER_THOUSAND[core::cmp::min(n.ilog2() as usize, 11)],
    };
    MSM_BASE_COST.saturating_add(
        MSM_PER_POINT_COST
            .saturating_mul(num_points)
            .saturating_mul(discount)
            .saturating_div(1000),
    )
}

pub fn pairing_cost(num_pairs: u64) -> u64 {
    PAIRING_BASE_COST.saturating_add(
        PAIRING_PER_PAIR_COST
            .saturating_add(G2_SUBGROUP_CHECK_COST)
            .saturating_mul(num_pairs),
    )
}

/// Register `sol_alt_bn128_g1_msm` and `sol_alt_bn128_pairing_check`.
///
/// **Must** run after `with_builtins()` and **before** `with_default_programs()`.
/// Prefer [`LiteSVM_with_batch_syscalls`] which builds a full environment in order.
pub fn with_batch_syscalls(svm: LiteSVM) -> LiteSVM {
    svm.with_custom_syscall("sol_alt_bn128_g1_msm", SyscallG1Msm::vm)
        .with_custom_syscall("sol_alt_bn128_pairing_check", SyscallPairingCheck::vm)
}

/// Build LiteSVM with the batch syscalls registered at the correct construction
/// point (after builtins, before default programs).
#[allow(non_snake_case)]
pub fn LiteSVM_with_batch_syscalls() -> LiteSVM {
    // Mirror LiteSVM::into_basic, inserting custom syscalls before programs.
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
    LiteSVM::default()
        .with_mainnet_features()
        .with_builtins()
        .with_custom_syscall("sol_alt_bn128_g1_msm", SyscallG1Msm::vm)
        .with_custom_syscall("sol_alt_bn128_pairing_check", SyscallPairingCheck::vm)
        .with_lamports(1_000_000u64.wrapping_mul(LAMPORTS_PER_SOL))
        .with_sysvars()
        .with_feature_accounts()
        .with_default_programs()
        .with_sigverify(true)
        .with_blockhash_check(true)
}

fn translate<'a>(
    memory_mapping: &'a MemoryMapping,
    vm_addr: u64,
    len: u64,
) -> Result<&'a [u8], Box<dyn std::error::Error>> {
    let host_addr: u64 = Result::from(memory_mapping.map(AccessType::Load, vm_addr, len))?;
    Ok(unsafe { std::slice::from_raw_parts(host_addr as *const u8, len as usize) })
}

// The returned slice aliases VM guest memory behind the mapping's host
// pointer, not the `MemoryMapping` struct itself, so `&mut` from `&` is sound
// here (mirrors agave's syscall translate helpers).
#[allow(clippy::mut_from_ref)]
fn translate_mut<'a>(
    memory_mapping: &'a MemoryMapping,
    vm_addr: u64,
    len: u64,
) -> Result<&'a mut [u8], Box<dyn std::error::Error>> {
    let host_addr: u64 = Result::from(memory_mapping.map(AccessType::Store, vm_addr, len))?;
    Ok(unsafe { std::slice::from_raw_parts_mut(host_addr as *const u8 as *mut u8, len as usize) })
}

fn pod_slice<T: bytemuck::Pod>(bytes: &[u8]) -> Result<&[T], Box<dyn std::error::Error>> {
    bytemuck::try_cast_slice(bytes)
        .map_err(|e| -> Box<dyn std::error::Error> { format!("pod cast: {e}").into() })
}

declare_builtin_function!(
    SyscallG1Msm,
    fn rust(
        invoke_context: &mut InvokeContext,
        num_points: u64,
        points_addr: u64,
        scalars_addr: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        invoke_context.consume_checked(msm_cost(num_points))?;
        let points_bytes = translate(memory_mapping, points_addr, num_points * G1_BYTES as u64)?;
        let scalars_bytes =
            translate(memory_mapping, scalars_addr, num_points * SCALAR_BYTES as u64)?;
        let points: &[PodG1Point] = pod_slice(points_bytes)?;
        let scalars: &[PodScalar] = pod_slice(scalars_bytes)?;
        match alt_bn128_g1_msm(Version::V0, points, scalars) {
            Ok(out) => {
                let dest = translate_mut(memory_mapping, result_addr, G1_BYTES as u64)?;
                dest.copy_from_slice(&out.0);
                Ok(0)
            }
            Err(_) => Ok(1),
        }
    }
);

declare_builtin_function!(
    SyscallPairingCheck,
    fn rust(
        invoke_context: &mut InvokeContext,
        num_pairs: u64,
        pairs_addr: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        invoke_context.consume_checked(pairing_cost(num_pairs))?;
        let pairs_bytes = translate(memory_mapping, pairs_addr, num_pairs * PAIR_BYTES as u64)?;
        let pairs: &[PodG1G2Pair] = pod_slice(pairs_bytes)?;
        match alt_bn128_pairing_check(Version::V0, pairs) {
            Ok(verdict) => {
                let dest = translate_mut(memory_mapping, result_addr, 32)?;
                let word = PodPairingResult::from_verdict(verdict);
                dest.copy_from_slice(&word.0);
                Ok(0)
            }
            Err(_) => Ok(1),
        }
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msm_cost_matches_agave_n1() {
        // base 100 + 3322 * 1 * 1000/1000
        assert_eq!(msm_cost(1), 100 + 3_322);
    }

    #[test]
    fn pairing_cost_n4() {
        assert_eq!(
            pairing_cost(4),
            17_246 + (5_741 + 3_595) * 4
        );
    }
}
