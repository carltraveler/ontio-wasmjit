use crate::resolver::Resolver;
use cranelift_wasm::DefinedMemoryIndex;
use hmac_sha256::Hash;
use libc;
use ontio_wasmjit_runtime::builtins::{catch_wasm_panic, check_host_panic};
use ontio_wasmjit_runtime::{wasmjit_unwind, VMContext, VMFunctionBody, VMFunctionImport};
use std::ffi::CString;
use std::panic;
use std::ptr;
use std::ptr::null_mut;
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicU64, Arc};

type Memptr = *mut u8;
type Error = u32;

pub type Address = [u8; 20];
pub type H256 = [u8; 32];

#[repr(C)]
pub struct Cgoerror {
    pub err: Error,
    pub errmsg: Memptr, //*String
}

#[repr(C)]
pub struct Cgou64 {
    pub v: u64,
    pub err: Error,
    pub errmsg: Memptr, //*String
}

#[repr(C)]
pub struct Cgou32 {
    pub v: u32,
    pub err: Error,
    pub errmsg: Memptr, //*String
}

#[repr(C)]
pub struct Cgobuffer {
    pub output: Memptr,
    pub outputlen: u32,
    pub err: Error,
    pub errmsg: Memptr, //*String
}

pub type Cgooutput = Cgobuffer; // errmsg *std::ffi::CString

extern "C" {
    fn ontio_debug_cgo(vmctx: Memptr, data_ptr: u32, l: u32) -> Cgoerror;
    fn ontio_notify_cgo(vmctx: Memptr, data_ptr: u32, l: u32) -> Cgoerror;
    fn ontio_call_contract_cgo(
        vmctx: Memptr,
        contract_addr: u32,
        input_ptr: u32,
        input_len: u32,
    ) -> Cgoerror;
}

#[repr(C)]
pub struct InterOpCtx {
    pub height: u32,
    pub block_hash: *mut u8,
    pub timestamp: u64,
    pub tx_hash: *mut u8,
    pub self_address: *mut u8,
    pub callers: *mut u8,
    pub callers_num: usize,
    pub witness: *mut u8,
    pub witness_num: usize,
    pub input: *mut u8,
    pub input_len: usize,
    pub wasmvm_service_ptr: u64,
    pub gas_left: u64,
    pub call_output: *mut u8,
    pub call_output_len: usize,
}

pub struct ChainCtx {
    pub height: u32,
    pub block_hash: H256,
    pub timestamp: u64,
    pub tx_hash: H256,
    pub self_address: Address,
    pub callers: Vec<Address>,
    pub witness: Vec<Address>,
    input: Vec<u8>,
    pub wasmvm_service_ptr: u64,
    pub(crate) gas_left: Arc<AtomicU64>,
    call_output: Vec<u8>,
    pub output: Memptr,
    pub outputlen: u32,
}

impl ChainCtx {
    pub fn new(
        timestamp: u64,
        height: u32,
        block_hash: H256,
        tx_hash: H256,
        self_address: Address,
        callers: Vec<Address>,
        witness: Vec<Address>,
        input: Vec<u8>,
        call_output: Vec<u8>,
        wasmvm_service_ptr: u64,
    ) -> Self {
        let gas_left = Arc::new(AtomicU64::new(u64::max_value()));

        Self {
            height,
            block_hash,
            timestamp,
            tx_hash,
            self_address,
            callers,
            witness,
            input,
            wasmvm_service_ptr,
            gas_left,
            call_output,
            output: null_mut(),
            outputlen: 0,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ontio_builtin_check_gas(vmctx: *mut VMContext, costs: u32) {
    check_host_panic(|| {
        let costs = costs as u64;
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        let origin = chain.gas_left.fetch_sub(costs, Ordering::Relaxed);

        if origin < costs {
            chain.gas_left.store(0, Ordering::Relaxed);
            panic!("wasmjit: gas exhausted");
        }
    })
}

/// Implementation of ontio_timestamp api
#[no_mangle]
pub unsafe extern "C" fn ontio_timestamp(vmctx: *mut VMContext) -> u64 {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        chain.timestamp
    })
}

/// Implementation of ontio_block_height api
#[no_mangle]
pub unsafe extern "C" fn ontio_block_height(vmctx: *mut VMContext) -> u32 {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        chain.height
    })
}

/// Implementation of ontio_current_blockhash api
#[no_mangle]
pub unsafe extern "C" fn ontio_current_blockhash(
    vmctx: *mut VMContext,
    block_hash_ptr: u32,
) -> u32 {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        let start = block_hash_ptr as usize;
        memory[start..start + chain.block_hash.len()].copy_from_slice(&chain.block_hash);
        32
    })
}

/// Implementation of ontio_current_txhash api
#[no_mangle]
pub unsafe extern "C" fn ontio_current_txhash(vmctx: *mut VMContext, tx_hash_ptr: u32) -> u32 {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        let start = tx_hash_ptr as usize;
        memory[start..start + &chain.tx_hash.len()].copy_from_slice(&chain.tx_hash);
        32
    })
}

/// Implementation of ontio_self_address api
#[no_mangle]
pub unsafe extern "C" fn ontio_self_address(vmctx: *mut VMContext, addr_ptr: u32) {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        let start = addr_ptr as usize;
        memory[start..start + 20].copy_from_slice(&chain.self_address);
    })
}

/// Implementation of ontio_caller_address api
#[no_mangle]
pub unsafe extern "C" fn ontio_caller_address(vmctx: *mut VMContext, caller_ptr: u32) {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        let start = caller_ptr as usize;
        let addr: Address = chain.callers.last().map(|v| *v).unwrap_or([0; 20]);
        memory[start..start + 20].copy_from_slice(&addr);
    })
}

/// Implementation of ontio_entry_address api
#[no_mangle]
pub unsafe extern "C" fn ontio_entry_address(vmctx: *mut VMContext, entry_ptr: u32) {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        let start = entry_ptr as usize;
        let addr: Address = chain.callers.first().map(|v| *v).unwrap_or([0; 20]);
        memory[start..start + 20].copy_from_slice(&addr);
    })
}

/// Implementation of ontio_check_witness api
#[no_mangle]
pub unsafe extern "C" fn ontio_check_witness(vmctx: *mut VMContext, addr_ptr: u32) -> u32 {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        let start = addr_ptr as usize;
        let mut addr: Address = [0; 20];
        addr.copy_from_slice(&memory[start..start + 20]);
        let res = chain.witness.iter().find(|&&x| x == addr);
        match res {
            Some(_) => 1,
            None => 0,
        }
    })
}

/// Implementation of ontio_input_length api
#[no_mangle]
pub unsafe extern "C" fn ontio_input_length(vmctx: *mut VMContext) -> u32 {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        chain.input.len() as u32
    })
}

/// Implementation of ontio_output_length api
#[no_mangle]
pub unsafe extern "C" fn ontio_call_output_length(vmctx: *mut VMContext) -> u32 {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        chain.call_output.len() as u32
    })
}

/// Implementation of ontio_get_input api
#[no_mangle]
pub unsafe extern "C" fn ontio_get_input(vmctx: *mut VMContext, input_ptr: u32) {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        let start = input_ptr as usize;
        memory[start..start + chain.input.len()].copy_from_slice(&chain.input);
    })
}

/// Implementation of ontio_get_call_out api
#[no_mangle]
pub unsafe extern "C" fn ontio_get_call_output(vmctx: *mut VMContext, dst_ptr: u32) {
    check_host_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        let start = dst_ptr as usize;
        memory[start..start + chain.call_output.len()].copy_from_slice(&chain.call_output);
    })
}

/// Implementation of ontio_panic api
#[no_mangle]
pub unsafe extern "C" fn ontio_panic(vmctx: *mut VMContext, input_ptr: u32, ptr_len: u32) {
    let msg = panic::catch_unwind(|| {
        println!("ontio_panic 00000");
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        let start = input_ptr as usize;
        let end = start
            .checked_add(ptr_len as usize)
            .expect("out of memory bound");
        String::from_utf8_lossy(&memory[start..end]).to_string()
    })
    .unwrap_or_else(|e| {
        let msg = if let Some(err) = e.downcast_ref::<String>() {
            err.to_string()
        } else if let Some(err) = e.downcast_ref::<&str>() {
            err.to_string()
        } else {
            "wasm host function paniced!".to_string()
        };

        msg
    });

    wasmjit_unwind(msg)
}

/// Implementation of ontio_sha256 api
#[no_mangle]
pub unsafe extern "C" fn ontio_sha256(vmctx: *mut VMContext, data_ptr: u32, l: u32, out_ptr: u32) {
    check_host_panic(|| {
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        let start = data_ptr as usize;
        let data = &memory[start..start + l as usize];
        let res = Hash::hash(data);
        let start = out_ptr as usize;
        memory[start..start + res.len()].copy_from_slice(&res);
    })
}

/// Implementation of ontio_debug api
#[no_mangle]
pub unsafe extern "C" fn ontio_debug(vmctx: *mut VMContext, data_ptr: u32, l: u32) {
    check_host_panic(|| {
        println!("ontio_debug enter");
        let err = ontio_debug_cgo(vmctx as Memptr, data_ptr, l);

        if err.err != 0 {
            panic!(*Box::from_raw(err.errmsg as *mut String));
        }
    })
}

/// Implementation of ontio_debug api
#[no_mangle]
pub unsafe extern "C" fn ontio_return(vmctx: *mut VMContext, data_ptr: u32, l: u32) {
    check_host_panic(|| {
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        // check here to avoid the memory attack in go.
        if memory.len() < (data_ptr + l) as usize {
            panic!("data_ptr over access");
        }

        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_mut::<ChainCtx>().unwrap();

        let outputbuffer = ontio_memalloc(l).unwrap();

        // only a ref. so buffer not drop here.
        let output = std::slice::from_raw_parts_mut(outputbuffer, l as usize);
        output.copy_from_slice(&memory[data_ptr as usize..(data_ptr + l) as usize]);

        chain.output = outputbuffer;
        chain.outputlen = l;
    })
}

/// Implementation of ontio_debug api
#[no_mangle]
pub unsafe extern "C" fn ontio_call_contract(
    vmctx: *mut VMContext,
    contract_addr: u32,
    input_ptr: u32,
    inputlen: u32,
) -> u32 {
    check_host_panic(|| {
        let err = ontio_call_contract_cgo(vmctx as Memptr, contract_addr, input_ptr, inputlen);
        if err.err != 0 {
            panic!(*Box::from_raw(err.errmsg as *mut String));
        }
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        chain.call_output.len() as u32
    })
}

/// Implementation of ontio_debug api
#[no_mangle]
pub unsafe extern "C" fn ontio_notify(vmctx: *mut VMContext, ptr: u32, l: u32) {
    check_host_panic(|| {
        let err = ontio_notify_cgo(vmctx as Memptr, ptr, l);
        if err.err != 0 {
            panic!(*Box::from_raw(err.errmsg as *mut String));
        }
    })
}

/// Interface for cgo read wasm vm memory.
#[no_mangle]
pub unsafe extern "C" fn ontio_read_wasmvm_memory(
    vmctx: *mut VMContext,
    data_ptr: u32,
    data_len: u32,
) -> Cgobuffer {
    let res = catch_wasm_panic(|| {
        let instance = (&mut *vmctx).instance();
        let memory = instance
            .memory_slice_mut(DefinedMemoryIndex::from_u32(0))
            .unwrap();
        if memory.len() < (data_ptr + data_len) as usize {
            panic!("ontio_read_wasmvm_memory out of bound");
        }
        // bound check to avoid memory attack.
        let buff = ontio_memalloc(data_len).unwrap();

        let outputbuff = std::slice::from_raw_parts_mut(buff, data_len as usize);
        outputbuff.copy_from_slice(&memory[data_ptr as usize..(data_ptr + data_len) as usize]);
        Ok(buff)
    });

    match res {
        Ok(buff) => Cgobuffer {
            output: buff,
            outputlen: data_len,
            err: 0,
            errmsg: null_mut(),
        }, //true
        Err(err_message) => Cgobuffer {
            output: null_mut(),
            outputlen: 0,
            err: 1,
            errmsg: Box::into_raw(Box::new(err_message)) as Memptr,
        }, //false
    }
}

/// Implementation of memoryread api
#[no_mangle]
pub unsafe extern "C" fn ontio_wasm_service_ptr(vmctx: *mut VMContext) -> Cgou64 {
    let res = catch_wasm_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_ref::<ChainCtx>().unwrap();
        Ok(chain.wasmvm_service_ptr)
    });

    match res {
        Ok(wasmvm_service_ptr) => Cgou64 {
            v: wasmvm_service_ptr,
            err: 0,
            errmsg: null_mut(),
        }, //true
        Err(err_message) => Cgou64 {
            v: 0,
            err: 1,
            errmsg: Box::into_raw(Box::new(err_message)) as Memptr,
        }, //false
    }
}

/// ontio_set_calloutput()
#[no_mangle]
pub unsafe extern "C" fn ontio_set_calloutput(
    vmctx: *mut VMContext,
    buff: Memptr,
    size: u32,
) -> Cgoerror {
    let res = catch_wasm_panic(|| {
        let host = (&mut *vmctx).host_state();
        let chain = host.downcast_mut::<ChainCtx>().unwrap();
        let v = std::slice::from_raw_parts(buff, size as usize).to_vec();
        chain.call_output = v;
        Ok(())
    });

    match res {
        Ok(..) => Cgoerror {
            err: 0,
            errmsg: null_mut(),
        },
        Err(err_message) => Cgoerror {
            err: 1,
            errmsg: Box::into_raw(Box::new(err_message)) as Memptr,
        },
    }
}

/// ontio_memalloc
#[no_mangle]
pub unsafe extern "C" fn ontio_memalloc(size: u32) -> Result<Memptr, String> {
    let ptr_t = libc::malloc(size as usize);
    if ptr_t as isize == -1_isize {
        return Err(String::from("alloc memory failed"));
    }

    Ok(ptr_t as Memptr)
}

/// ontio_error
#[no_mangle]
pub unsafe extern "C" fn ontio_error(ptr: *mut u8, len: u32) -> Cgoerror {
    let res = catch_wasm_panic(|| {
        let v = std::slice::from_raw_parts(ptr, len as usize).to_vec();
        Ok(Cgoerror {
            err: 1,
            errmsg: Box::into_raw(Box::new(
                CString::from_vec_unchecked(v).into_string().unwrap(),
            )) as Memptr,
        })
    });

    match res {
        Ok(err) => err,
        Err(err_message) => Cgoerror {
            err: 1,
            errmsg: Box::into_raw(Box::new(err_message)) as Memptr,
        },
    }
}

/// ontio_memfree
#[no_mangle]
pub unsafe extern "C" fn ontio_memfree(ptr: Memptr) {
    if ptr.is_null() {
        return;
    }
    let ptr = libc::free(ptr as *mut core::ffi::c_void);
}

/// ontio_free_cgooutput
#[no_mangle]
pub unsafe extern "C" fn ontio_free_cgooutput(output: Cgooutput) {
    unsafe {
        ontio_memfree(output.output);

        if output.errmsg.is_null() {
            return;
        }

        CString::from_raw(output.errmsg as *mut i8)
    };
}

/*
const SIGNATURES: [(&str, &[ValueType], Option<ValueType>); 24] = [
    ("ontio_call_output_length", &[], Some(ValueType::I32)),
    ("ontio_get_call_output", &[ValueType::I32], None),
    ("ontio_self_address", &[ValueType::I32], None),
    ("ontio_caller_address", &[ValueType::I32], None),
    ("ontio_entry_address", &[ValueType::I32], None),
    ("ontio_check_witness", &[ValueType::I32], Some(ValueType::I32)),
    ("ontio_current_blockhash", &[ValueType::I32], Some(ValueType::I32)),
    ("ontio_current_txhash", &[ValueType::I32], Some(ValueType::I32)),
    ("ontio_return", &[ValueType::I32; 2], None),
    ("ontio_panic", &[ValueType::I32; 2], None),
    ("ontio_notify", &[ValueType::I32; 2], None),
    ("ontio_call_contract", &[ValueType::I32; 3], Some(ValueType::I32)),
    ("ontio_contract_create", &[ValueType::I32; 14], Some(ValueType::I32)),
    ("ontio_contract_migrate", &[ValueType::I32; 14], Some(ValueType::I32)),
    ("ontio_contract_destroy", &[], None),
    ("ontio_storage_read", &[ValueType::I32; 5], Some(ValueType::I32)),
    ("ontio_storage_write", &[ValueType::I32; 4], None),
    ("ontio_storage_delete", &[ValueType::I32; 2], None),
    ("ontio_debug", &[ValueType::I32; 2], None),
    ("ontio_sha256", &[ValueType::I32; 3], None),
];
*/

pub struct ChainResolver;

impl Resolver for ChainResolver {
    fn resolve(&mut self, _module: &str, field: &str) -> Option<VMFunctionImport> {
        match field {
            "ontio_timestamp" => Some(VMFunctionImport {
                body: ontio_timestamp as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_block_height" => Some(VMFunctionImport {
                body: ontio_block_height as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_input_length" => Some(VMFunctionImport {
                body: ontio_input_length as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_call_output_length" => Some(VMFunctionImport {
                body: ontio_call_output_length as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_get_input" => Some(VMFunctionImport {
                body: ontio_get_input as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_current_blockhash" => Some(VMFunctionImport {
                body: ontio_current_blockhash as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_current_txhash" => Some(VMFunctionImport {
                body: ontio_current_txhash as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_self_address" => Some(VMFunctionImport {
                body: ontio_self_address as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_caller_address" => Some(VMFunctionImport {
                body: ontio_caller_address as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_entry_address" => Some(VMFunctionImport {
                body: ontio_entry_address as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_check_witness" => Some(VMFunctionImport {
                body: ontio_check_witness as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_sha256" => Some(VMFunctionImport {
                body: ontio_sha256 as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_get_call_output" => Some(VMFunctionImport {
                body: ontio_get_call_output as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_panic" => Some(VMFunctionImport {
                body: ontio_panic as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_debug" => Some(VMFunctionImport {
                body: ontio_debug as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_return" => Some(VMFunctionImport {
                body: ontio_return as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_call_contract" => Some(VMFunctionImport {
                body: ontio_call_contract as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            "ontio_notify" => Some(VMFunctionImport {
                body: ontio_notify as *const VMFunctionBody,
                vmctx: ptr::null_mut(),
            }),
            _ => None,
        }
    }
}
