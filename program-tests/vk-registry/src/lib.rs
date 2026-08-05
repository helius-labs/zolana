//! LiteSVM harness for the stateless prepared-operand syscalls.
//!
//! The shims delegate their math to the fork's `solana-bn254-batch-syscall`
//! backend and charge the fork validator's lane tariff, so CU assertions in
//! tests match what the fork runtime would charge. Only test builds link
//! this; a stock validator never sees these syscalls, which is why the
//! program feature `vk-registry` is default-off.

use litesvm::LiteSVM;
use solana_bn254_batch_syscall::{
    g2_prepare, pairing_check_prepared, pairing_check_prepared_vs_target, pairing_map_prepared,
    prepared_g2_from_wire, unpack_g2_prepare_shape, unpack_prepared_pairing_shape, PodG1G2Pair,
    PodG1Point, PodG1PreparedG2Pair, PodGtElement, PodPairingResult, FQ12_BYTES,
    MAX_PREPARED_PAIRS, PAIRING_MAP_MAX_PAIRS, PAIRING_MAX_PAIRS, PAIR_BYTES,
    PREPARED_G2_WIRE_BYTES,
};
use solana_program_runtime::{
    invoke_context::InvokeContext,
    solana_sbpf::{
        declare_builtin_function,
        elf::ElfError,
        memory_region::{AccessType, MemoryMapping},
        program::BuiltinProgram,
    },
};

type Ctx = InvokeContext<'static, 'static>;

fn register_g2_prepare(program: &mut BuiltinProgram<Ctx>, name: &str) -> Result<(), ElfError> {
    program.register_definition::<SyscallG2Prepare>(name)
}

fn register_check_prepared(program: &mut BuiltinProgram<Ctx>, name: &str) -> Result<(), ElfError> {
    program.register_definition::<SyscallPairingCheckPrepared>(name)
}

fn register_map_prepared(program: &mut BuiltinProgram<Ctx>, name: &str) -> Result<(), ElfError> {
    program.register_definition::<SyscallPairingMapPrepared>(name)
}

fn register_map(program: &mut BuiltinProgram<Ctx>, name: &str) -> Result<(), ElfError> {
    program.register_definition::<SyscallPairingMap>(name)
}

pub const RUNTIME_PAIRING_BASE_CU: u64 = 4_641;
pub const RUNTIME_PAIRING_PER_PAIR_CU: u64 = 4_188;
pub const RUNTIME_PAIRING_LANE_CU: u64 = 20_338;
pub const RUNTIME_PREPARED_SCALAR_CREDIT_CU: u64 = 2_200;
pub const RUNTIME_PREPARED_LANE_CREDIT_CU: u64 = 750;
pub const RUNTIME_G2_PREPARE_CU: u64 = 700 + 4_188;

/// Mirrors the fork's `alt_bn128_pairing_cost_prepared`.
pub fn prepared_pairing_cu(full: u64, prepared: u64) -> u64 {
    let pairs = full.saturating_add(prepared);
    let lanes = pairs / 8;
    let remainder = pairs % 8;
    let credit = if lanes == 0 {
        RUNTIME_PREPARED_SCALAR_CREDIT_CU
    } else {
        RUNTIME_PREPARED_LANE_CREDIT_CU
    };
    RUNTIME_PAIRING_BASE_CU
        .saturating_add(RUNTIME_PAIRING_LANE_CU.saturating_mul(lanes))
        .saturating_add(RUNTIME_PAIRING_PER_PAIR_CU.saturating_mul(remainder))
        .saturating_sub(credit.saturating_mul(prepared))
}

/// Install the three prepared-operand syscalls plus the full-pair map the
/// init flow uses for its GT target. Must run before `add_program`.
pub fn with_prepared_syscalls(svm: LiteSVM) -> LiteSVM {
    svm.with_custom_syscall("sol_alt_bn128_g2_prepare", register_g2_prepare)
        .with_custom_syscall(
            "sol_alt_bn128_pairing_check_prepared",
            register_check_prepared,
        )
        .with_custom_syscall("sol_alt_bn128_pairing_map_prepared", register_map_prepared)
        .with_custom_syscall("sol_alt_bn128_pairing_map", register_map)
}

fn translate(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
) -> Result<&[u8], Box<dyn std::error::Error>> {
    let host_addr: u64 = Result::from(memory_mapping.map(AccessType::Load, vm_addr, len))?;
    Ok(unsafe { std::slice::from_raw_parts(host_addr as *const u8, len as usize) })
}

#[allow(clippy::mut_from_ref)]
fn translate_mut(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
) -> Result<&mut [u8], Box<dyn std::error::Error>> {
    let host_addr: u64 = Result::from(memory_mapping.map(AccessType::Store, vm_addr, len))?;
    Ok(unsafe { std::slice::from_raw_parts_mut(host_addr as *mut u8, len as usize) })
}

fn pod_slice<T: bytemuck::Pod>(bytes: &[u8]) -> Result<&[T], Box<dyn std::error::Error>> {
    bytemuck::try_cast_slice(bytes).map_err(|error| format!("pod cast failed: {error}").into())
}

type PreparedOperands<'a> = (&'a [PodG1G2Pair], Vec<(PodG1Point, &'a [u8])>);

fn translate_prepared_operands<'a>(
    memory_mapping: &'a MemoryMapping,
    full_addr: u64,
    prepared_addr: u64,
    full_count: u16,
    prepared_count: u16,
) -> Result<PreparedOperands<'a>, Box<dyn std::error::Error>> {
    let full: &[PodG1G2Pair] = if full_count == 0 {
        &[]
    } else {
        pod_slice(translate(
            memory_mapping,
            full_addr,
            u64::from(full_count) * PAIR_BYTES as u64,
        )?)?
    };
    let records: &[PodG1PreparedG2Pair] = if prepared_count == 0 {
        &[]
    } else {
        pod_slice(translate(
            memory_mapping,
            prepared_addr,
            u64::from(prepared_count) * core::mem::size_of::<PodG1PreparedG2Pair>() as u64,
        )?)?
    };
    let mut prepared = Vec::with_capacity(records.len());
    for record in records {
        if record.prepared.blob_len() != PREPARED_G2_WIRE_BYTES as u64 {
            return Err("prepared blob length mismatch".into());
        }
        let blob = translate(
            memory_mapping,
            record.prepared.addr(),
            PREPARED_G2_WIRE_BYTES as u64,
        )?;
        prepared.push((record.g1, blob));
    }
    Ok((full, prepared))
}

fn restore_prepared(
    prepared: &[(PodG1Point, &[u8])],
) -> Result<Vec<solana_bn254_batch_syscall::PreparedG2>, Box<dyn std::error::Error>> {
    prepared
        .iter()
        .map(|(_, blob)| prepared_g2_from_wire(blob).map_err(Into::into))
        .collect()
}

declare_builtin_function!(
    SyscallG2Prepare,
    fn rust(
        invoke_context: &mut InvokeContext<'_, '_>,
        packed_shape: u64,
        g2_source_addr: u64,
        prepared_out_addr: u64,
        _arg4: u64,
        _arg5: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        invoke_context
            .compute_meter
            .consume_checked(RUNTIME_G2_PREPARE_CU)?;
        if !unpack_g2_prepare_shape(packed_shape) {
            return Ok(1);
        }
        let memory_mapping = invoke_context.memory_contexts.memory_mapping()?;
        let source = translate(memory_mapping, g2_source_addr, 128)?;
        let source: [u8; 128] = source.try_into()?;
        let Ok(prepared) = g2_prepare(&solana_bn254_batch_syscall::PodG2Point(source)) else {
            return Ok(1);
        };
        translate_mut(
            memory_mapping,
            prepared_out_addr,
            PREPARED_G2_WIRE_BYTES as u64,
        )?
        .copy_from_slice(&prepared.to_wire_bytes());
        Ok(0)
    }
);

declare_builtin_function!(
    SyscallPairingCheckPrepared,
    fn rust(
        invoke_context: &mut InvokeContext<'_, '_>,
        packed_shape: u64,
        full_addr: u64,
        prepared_addr: u64,
        target_addr: u64,
        result_addr: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let Some((full_count, prepared_count)) = unpack_prepared_pairing_shape(packed_shape) else {
            return Ok(1);
        };
        let total = usize::from(full_count) + usize::from(prepared_count);
        if prepared_count == 0
            || total > PAIRING_MAX_PAIRS
            || usize::from(prepared_count) > MAX_PREPARED_PAIRS
        {
            return Ok(1);
        }
        invoke_context
            .compute_meter
            .consume_checked(prepared_pairing_cu(
                u64::from(full_count),
                u64::from(prepared_count),
            ))?;
        let memory_mapping = invoke_context.memory_contexts.memory_mapping()?;
        let (full, prepared) = match translate_prepared_operands(
            memory_mapping,
            full_addr,
            prepared_addr,
            full_count,
            prepared_count,
        ) {
            Ok(operands) => operands,
            Err(_) => return Ok(1),
        };
        let Ok(handles) = restore_prepared(&prepared) else {
            return Ok(1);
        };
        let refs: Vec<_> = prepared
            .iter()
            .zip(&handles)
            .map(|((g1, _), handle)| (*g1, handle))
            .collect();
        let verdict = if target_addr == 0 {
            pairing_check_prepared(full, &refs)
        } else {
            let bytes = translate(memory_mapping, target_addr, FQ12_BYTES as u64)?;
            let target = PodGtElement(bytes.try_into()?);
            pairing_check_prepared_vs_target(full, &refs, &target)
        };
        let Ok(verdict) = verdict else {
            return Ok(1);
        };
        translate_mut(memory_mapping, result_addr, 32)?
            .copy_from_slice(&PodPairingResult::from_verdict(verdict).0);
        Ok(0)
    }
);

declare_builtin_function!(
    SyscallPairingMapPrepared,
    fn rust(
        invoke_context: &mut InvokeContext<'_, '_>,
        packed_shape: u64,
        full_addr: u64,
        prepared_addr: u64,
        result_addr: u64,
        _arg5: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let Some((full_count, prepared_count)) = unpack_prepared_pairing_shape(packed_shape) else {
            return Ok(1);
        };
        let total = usize::from(full_count) + usize::from(prepared_count);
        if prepared_count == 0
            || total > PAIRING_MAP_MAX_PAIRS
            || usize::from(prepared_count) > MAX_PREPARED_PAIRS
        {
            return Ok(1);
        }
        invoke_context
            .compute_meter
            .consume_checked(prepared_pairing_cu(
                u64::from(full_count),
                u64::from(prepared_count),
            ))?;
        let memory_mapping = invoke_context.memory_contexts.memory_mapping()?;
        let (full, prepared) = match translate_prepared_operands(
            memory_mapping,
            full_addr,
            prepared_addr,
            full_count,
            prepared_count,
        ) {
            Ok(operands) => operands,
            Err(_) => return Ok(1),
        };
        let Ok(handles) = restore_prepared(&prepared) else {
            return Ok(1);
        };
        let refs: Vec<_> = prepared
            .iter()
            .zip(&handles)
            .map(|((g1, _), handle)| (*g1, handle))
            .collect();
        let Ok(mapped) = pairing_map_prepared(full, &refs) else {
            return Ok(1);
        };
        translate_mut(memory_mapping, result_addr, FQ12_BYTES as u64)?.copy_from_slice(&mapped.0);
        Ok(0)
    }
);

declare_builtin_function!(
    /// Full-pair map, used at init time for the cached GT target. Charged at
    /// the plain lane tariff (no credits; all pairs are full).
    SyscallPairingMap,
    fn rust(
        invoke_context: &mut InvokeContext<'_, '_>,
        num_pairs: u64,
        pairs_addr: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        invoke_context.compute_meter.consume_checked(prepared_pairing_cu(num_pairs, 0))?;
        if num_pairs == 0 || num_pairs as usize > PAIRING_MAP_MAX_PAIRS {
            return Ok(1);
        }
        let memory_mapping = invoke_context.memory_contexts.memory_mapping()?;
        let pairs: &[PodG1G2Pair] = pod_slice(translate(
            memory_mapping,
            pairs_addr,
            num_pairs * PAIR_BYTES as u64,
        )?)?;
        let Ok(mapped) = solana_bn254_batch_syscall::alt_bn128_pairing_map(
            solana_bn254_batch_syscall::Version::V0,
            pairs,
        ) else {
            return Ok(1);
        };
        translate_mut(memory_mapping, result_addr, FQ12_BYTES as u64)?
            .copy_from_slice(&mapped.0);
        Ok(0)
    }
);
