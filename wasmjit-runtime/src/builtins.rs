#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
//! Runtime library calls. Note that wasm compilers may sometimes perform these
//! inline rather than calling them, particularly when CPUs have special
//! instructions which compute them directly.

use crate::instance::Instance;
use crate::vmcontext::VMContext;
use crate::wasmjit_unwind;
use cranelift_wasm::DefinedMemoryIndex;
use std::panic::{self, AssertUnwindSafe};

/// trap_kind
pub type wasmjit_result_kind = u32;
/// success
pub const wasmjit_result_success: wasmjit_result_kind = 0;
/// internal
pub const wasmjit_result_err_internal: wasmjit_result_kind = 1;
/// compile
pub const wasmjit_result_err_compile: wasmjit_result_kind = 2;
/// link
pub const wasmjit_result_err_link: wasmjit_result_kind = 3;
/// trap
pub const wasmjit_result_err_trap: wasmjit_result_kind = 4;

/// inner trap
pub struct wasmjit_trap {
    /// kind
    pub kind: wasmjit_result_kind,
    /// msg
    pub msg: String,
}

/// catch panic of rust host/builtins function.
pub fn check_host_panic<F, U>(instance: &mut Instance, func: F) -> U
where
    F: FnOnce(&mut Instance) -> U + panic::UnwindSafe,
{
    panic::catch_unwind(panic::AssertUnwindSafe(|| func(instance))).unwrap_or_else(|e| {
        instance.set_trap_kind(wasmjit_result_err_trap);
        let msg = if let Some(err) = e.downcast_ref::<String>() {
            err.to_string()
        } else if let Some(err) = e.downcast_ref::<&str>() {
            (*err).to_string()
        } else if let Some(trap) = e.downcast_ref::<wasmjit_trap>() {
            instance.set_trap_kind(trap.kind);
            trap.msg.to_string()
        } else {
            "wasm host function paniced!".to_string()
        };

        unsafe { wasmjit_unwind(msg) }
    })
}

/// catch panic of rust host/builtins function.
pub fn check_internel_panic<F, U>(f: F) -> Result<U, String>
where
    F: FnOnce() -> Result<U, String>,
{
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|e| {
        let msg = if let Some(err) = e.downcast_ref::<String>() {
            err.to_string()
        } else if let Some(err) = e.downcast_ref::<&str>() {
            (*err).to_string()
        } else {
            "wasm host function paniced!".to_string()
        };

        Err(msg)
    })
}

/// Implementation of memory.grow for locally-defined 32-bit memories.
#[no_mangle]
pub unsafe extern "C" fn wasmjit_memory32_grow(
    vmctx: *mut VMContext,
    delta: u32,
    memory_index: u32,
) -> u32 {
    check_host_panic((&mut *vmctx).instance(), |instance| {
        instance
            .memory_grow(DefinedMemoryIndex::from_u32(memory_index), delta)
            .unwrap_or(u32::max_value())
    })
}

/// Implementation of memory.size for locally-defined 32-bit memories.
#[no_mangle]
pub unsafe extern "C" fn wasmjit_memory32_size(vmctx: *mut VMContext, memory_index: u32) -> u32 {
    check_host_panic((&mut *vmctx).instance(), |instance| {
        instance.memory_size(DefinedMemoryIndex::from_u32(memory_index))
    })
}

/// Implementation of check gas
#[no_mangle]
pub unsafe extern "C" fn wasmjit_check_gas(vmctx: *mut VMContext, costs: u32) {
    let instance = (&mut *vmctx).instance();

    let costs = costs as u64;
    if instance.exec_metrics.exec_step_left < costs {
        instance.exec_metrics.exec_step_left = 0;
        instance.set_trap_kind(wasmjit_result_err_trap);
        let msg = String::from("wasmjit: exec step exhausted");
        wasmjit_unwind(msg)
    } else {
        instance.exec_metrics.exec_step_left -= costs;
    }

    instance.local_gas_counter += costs;
    let gas_factor = instance.exec_metrics.gas_factor;

    let normalize_costs = instance.local_gas_counter / gas_factor;
    if normalize_costs == 0 {
        return;
    }

    instance.local_gas_counter %= gas_factor;
    if !instance.check_gas(normalize_costs) {
        instance.set_trap_kind(wasmjit_result_err_trap);
        let msg = String::from("wasmjit: gas exhausted");
        wasmjit_unwind(msg)
    }
}

/// Implementation of check gas
#[no_mangle]
pub unsafe extern "C" fn wasmjit_check_depth(vmctx: *mut VMContext, count: i32) {
    let instance = (&mut *vmctx).instance();
    let origin = instance.exec_metrics.depth_left;

    if count > 0 {
        instance.exec_metrics.depth_left -= count as u64;
    } else {
        instance.exec_metrics.depth_left += -count as u64;
    }

    if origin == 0 {
        instance.exec_metrics.depth_left = 0;
        instance.set_trap_kind(wasmjit_result_err_trap);
        let msg = String::from("wasmjit: out of function calling depth limitation");
        wasmjit_unwind(msg)
    }
}
