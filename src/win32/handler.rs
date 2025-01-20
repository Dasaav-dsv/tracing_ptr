use std::{
    cell::UnsafeCell,
    ffi::c_void,
    io::Write,
    mem,
    num::{NonZero, NonZeroI32},
    ptr::{self, NonNull},
    slice,
    sync::LazyLock,
};

use windows::Win32::{
    Foundation::{EXCEPTION_ACCESS_VIOLATION, EXCEPTION_SINGLE_STEP},
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, CONTEXT, EXCEPTION_POINTERS, EXCEPTION_RECORD,
        },
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
    },
};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfo, InstructionInfoFactory,
    Register,
};

use super::{
    context::GetRegistersCONTEXT, named_mmap, tracing::TRACE_PTR_MASK,
    tracing_manager::TRACING_MANAGER,
};

#[inline]
pub fn add_handler() {
    named_mmap::ref_current_module().unwrap();
    unsafe {
        if false {
            hook_ki_user_exception_dispatcher();
        } else {
            AddVectoredExceptionHandler(1, Some(exception_handler));
        }
    }
}

unsafe extern "system" fn exception_handler(exception_pointers: *mut EXCEPTION_POINTERS) -> i32 {
    thread_local! {
        static LOCAL_HANDLER: UnsafeCell<ThreadLocalHandler> = UnsafeCell::default();
    }

    // SAFETY: LOCAL_HANDLER_CONTEXT is thread local and externally invisible
    // ensuring reference exclusivity.
    let handler = unsafe { LOCAL_HANDLER.with(UnsafeCell::get).as_mut().unwrap() };

    handler
        .handle_exception(exception_pointers)
        .map(NonZero::get)
        .unwrap_or_default()
}

unsafe fn hook_ki_user_exception_dispatcher() {
    unsafe {
        let handle = GetModuleHandleW(windows::core::w!("ntdll.dll")).unwrap();

        let pointer = handle.0.map_addr(|a| a + 0x181230);

        VirtualProtect(pointer, 8, PAGE_EXECUTE_READWRITE, &mut Default::default()).unwrap();

        pointer
            .cast::<unsafe extern "system" fn(*mut EXCEPTION_RECORD, *mut CONTEXT)>()
            .write(wow64_prepare_for_exception_hook);
    }
}

unsafe extern "system" {
    unsafe fn wow64_prepare_for_exception_hook(
        record: *mut EXCEPTION_RECORD,
        context: *mut CONTEXT,
    );
}

std::arch::global_asm!(
    ".global wow64_prepare_for_exception_hook",
    "wow64_prepare_for_exception_hook:",
    "sub rsp,0x38",
    "mov [rsp+0x20],rcx",
    "mov [rsp+0x28],rdx",
    "lea rcx,[rsp+0x20]",
    "call {}",
    "cmp eax,-1",
    "je 2f",
    "add rsp,0x38",
    "ret",
    "2:",
    "call {}",
    "xor edx,edx",
    "mov rcx,[rsp+0x28]",
    "add rsp,0x38",
    "jmp rax",
    sym exception_handler,
    sym get_rtl_restore_context,
);

unsafe extern "system" fn get_rtl_restore_context() -> unsafe extern "system" fn() -> isize {
    static RTL_RESTORE_CONTEXT: LazyLock<unsafe extern "system" fn() -> isize> =
        LazyLock::new(|| unsafe {
            let handle = GetModuleHandleW(windows::core::w!("ntdll.dll")).unwrap();
            GetProcAddress(handle, windows::core::s!("RtlRestoreContext")).unwrap()
        });

    RTL_RESTORE_CONTEXT.clone()
}

type HandlerResult = Option<NonZeroI32>;

const EXCEPTION_CONTINUE_EXECUTION: HandlerResult = Some(NonZeroI32::new(-1).unwrap());
const EXCEPTION_CONTINUE_SEARCH: HandlerResult = None;

#[derive(Default)]
struct ThreadLocalHandler {
    next_ip: Option<u64>,
    restore: Option<(Register, u64, u64)>,
    execute: ExecuteHandler,
}

impl ThreadLocalHandler {
    #[inline]
    fn handle_exception(&mut self, exception_pointers: *mut EXCEPTION_POINTERS) -> HandlerResult {
        let record = unsafe { &*(*exception_pointers).ExceptionRecord };
        let context = unsafe { &mut *(*exception_pointers).ContextRecord };

        match record.ExceptionCode {
            EXCEPTION_ACCESS_VIOLATION => self.handle_access_violation(context),
            EXCEPTION_SINGLE_STEP => self.handle_single_step(context),
            _ => EXCEPTION_CONTINUE_SEARCH,
        }
    }

    #[inline]
    fn handle_access_violation(&mut self, context: &mut CONTEXT) -> HandlerResult {
        let mut decoder = Decoder::with_ip(
            64,
            unsafe { slice::from_raw_parts(ptr::with_exposed_provenance(context.Rip as _), 15) },
            context.Rip,
            DecoderOptions::NONE,
        );

        let mut instruction_info_factory = InstructionInfoFactory::new();

        let instruction = decoder.decode();
        let instruction_info = instruction_info_factory.info(&instruction);

        let Some((used_memory, exception_address, tracer)) = instruction_info
            .used_memory()
            .iter()
            .filter_map(|m| Some((m, context.get_virtual_address(m)?)))
            .find_map(|(m, a)| {
                Some((
                    m,
                    a,
                    TRACING_MANAGER.get((a as usize >> 47).try_into().ok()?)?,
                ))
            })
        else {
            return match instruction.flow_control() {
                FlowControl::IndirectBranch => {
                    self.execute_indirect_jump(context, &instruction, &instruction_info)
                }
                FlowControl::IndirectCall => {
                    self.execute_indirect_call(context, &instruction, &instruction_info)
                }
                _ => EXCEPTION_CONTINUE_SEARCH,
            };
        };

        let actual_address = exception_address & TRACE_PTR_MASK as u64;

        let base_register = used_memory.base().full_register();
        let base_address = match base_register {
            Register::RIP => context.get_ip_mut(),
            r => context.get_gpr_mut(r).unwrap(),
        };

        let delta = exception_address.wrapping_sub(*base_address);
        *base_address = actual_address.wrapping_sub(delta);

        let restore = (base_register, actual_address, *base_address);

        tracer(&instruction, instruction_info, context, actual_address);

        if instruction.flow_control() == FlowControl::Next {
            if instruction_info
                .used_registers()
                .iter()
                .all(|r| r.register() <= Register::R15)
            {
                self.execute_instruction_and_restore_context(&instruction, context, restore);
            } else {
                self.prepare_single_step_and_save_context(&instruction, context, restore);
            }
        }

        EXCEPTION_CONTINUE_EXECUTION
    }

    #[inline]
    fn handle_single_step(&mut self, context: &mut CONTEXT) -> HandlerResult {
        let _ = self.next_ip.take_if(|a| *a == context.get_ip())?;

        Self::restore_context(
            self.restore.take().expect("saved context to restore"),
            context,
        );

        EXCEPTION_CONTINUE_EXECUTION
    }

    #[inline]
    fn restore_context((register, cmp, chg): (Register, u64, u64), context: &mut CONTEXT) {
        if let Some(r) = context.get_gpr_mut(register).filter(|r| **r == cmp) {
            *r = chg;
        }
    }

    #[inline]
    fn execute_instruction_and_restore_context(
        &mut self,
        instruction: &Instruction,
        context: &mut CONTEXT,
        restore: (Register, u64, u64),
    ) {
        assert!(
            self.restore.is_none() && self.next_ip.is_none(),
            "Thread context has not been restored properly.
Did a debugger handle a tracing_ptr single step exception?
The unhandled instruction was at {:016X?}",
            self.next_ip
        );

        self.execute
            .execute_instruction_with_context(instruction, context);

        Self::restore_context(restore, context);

        *context.get_ip_mut() = instruction.next_ip();
    }

    #[inline]
    fn prepare_single_step_and_save_context(
        &mut self,
        instruction: &Instruction,
        context: &mut CONTEXT,
        restore: (Register, u64, u64),
    ) {
        assert!(
            self.restore.replace(restore).is_none()
                && self.next_ip.replace(instruction.next_ip()).is_none(),
            "Thread context has not been restored properly.
Did a debugger handle a tracing_ptr single step exception?
The unhandled instruction was at {:016X?}",
            self.next_ip
        );

        context.EFlags |= 0x0100;
    }

    #[inline]
    fn execute_indirect_call(
        &mut self,
        context: &mut CONTEXT,
        instruction: &Instruction,
        instruction_info: &InstructionInfo,
    ) -> HandlerResult {
        self.execute_indirect_jump(context, instruction, instruction_info)?;

        context.Rsp -= 8;

        unsafe {
            ptr::with_exposed_provenance_mut::<u64>(context.Rsp as usize)
                .write(instruction.next_ip());
        }

        EXCEPTION_CONTINUE_EXECUTION
    }

    #[inline]
    fn execute_indirect_jump(
        &mut self,
        context: &mut CONTEXT,
        instruction: &Instruction,
        instruction_info: &InstructionInfo,
    ) -> HandlerResult {
        assert!(
            self.restore.is_none() && self.next_ip.is_none(),
            "Thread context has not been restored properly.
Did a debugger handle a tracing_ptr single step exception?
The unhandled instruction was at {:016X?}",
            self.next_ip
        );

        let used_memory = instruction_info.used_memory().first()?;

        let exception_address = unsafe {
            ptr::with_exposed_provenance::<u64>(context.get_virtual_address(used_memory)? as _)
                .read()
        };

        let actual_address = exception_address & TRACE_PTR_MASK as u64;

        let tracer = TRACING_MANAGER.get((exception_address as usize >> 47).try_into().ok()?)?;
        tracer(&instruction, instruction_info, context, actual_address);

        context.Rip = actual_address;

        EXCEPTION_CONTINUE_EXECUTION
    }
}

#[repr(C)]
struct ExecuteHandler {
    code: unsafe extern "system" fn(*mut CONTEXT),
    instruction_buf: NonNull<[u8; 64]>,
}

impl ExecuteHandler {
    fn execute_instruction_with_context(
        &mut self,
        instruction: &Instruction,
        context: &mut CONTEXT,
    ) {
        unsafe {
            let mut instruction_buf = self.instruction_buf.as_mut().as_mut_slice();

            instruction_buf
                .write(slice::from_raw_parts(
                    ptr::with_exposed_provenance(instruction.ip() as _),
                    instruction.len(),
                ))
                .unwrap_unchecked();

            let jmp_instruction = [0xEB, 64 - 2 - instruction.len() as u8];

            instruction_buf.write(&jmp_instruction).unwrap_unchecked();

            (self.code)(context);
        }
    }
}

impl Default for ExecuteHandler {
    fn default() -> Self {
        unsafe {
            let execute_handler_len = (&raw const execute_handler_prototype_end as *const c_void)
                .byte_offset_from(&raw const execute_handler_prototype as *const c_void)
                .try_into()
                .unwrap();

            let instruction_base = (&raw const execute_handler_instruction_base as *const c_void)
                .byte_offset_from(&raw const execute_handler_prototype as *const c_void)
                .try_into()
                .unwrap();

            let code = slice::from_raw_parts_mut(
                VirtualAlloc(
                    None,
                    execute_handler_len,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
                .cast::<u8>(),
                execute_handler_len,
            );

            code.copy_from_slice(slice::from_raw_parts(
                &raw const execute_handler_prototype as _,
                execute_handler_len,
            ));

            let code = code.as_mut_ptr();
            let instruction_buf = NonNull::new(code.byte_offset(instruction_base))
                .unwrap()
                .cast();

            Self {
                code: mem::transmute(code),
                instruction_buf,
            }
        }
    }
}

unsafe extern "C" {
    static execute_handler_prototype: c_void;
    static execute_handler_instruction_base: c_void;
    static execute_handler_prototype_end: c_void;
}

std::arch::global_asm!(
    ".global execute_handler_prototype",
    ".global execute_handler_instruction_base",
    ".global execute_handler_prototype_end",
    ".balign 0x40, 0x90",
    "execute_handler_prototype:",
    "sub rsp,0x68",
    "movq xmm0,rsp",
    "mov [rsp],rcx",
    "mov [rsp+0x8],rbx",
    "mov [rsp+0x10],rbp",
    "mov [rsp+0x18],rsi",
    "mov [rsp+0x20],rdi",
    "mov [rsp+0x28],r12",
    "mov [rsp+0x30],r13",
    "mov [rsp+0x38],r14",
    "mov [rsp+0x40],r15",
    ".byte 0x40",
    "mov eax,[rcx+0x44]",
    ".byte 0x40",
    "push rax",
    ".byte 0x40",
    "popf",
    "lea rcx,[rcx+0x78]",
    "mov rax,[rcx]",
    "mov rdx,[rcx+0x10]",
    "mov rbx,[rcx+0x18]",
    "mov rsp,[rcx+0x20]",
    "mov rbp,[rcx+0x28]",
    "mov rsi,[rcx+0x30]",
    "mov rdi,[rcx+0x38]",
    "mov r8,[rcx+0x40]",
    "mov r9,[rcx+0x48]",
    "mov r10,[rcx+0x50]",
    "mov r11,[rcx+0x58]",
    "mov r12,[rcx+0x60]",
    "mov r13,[rcx+0x68]",
    "mov r14,[rcx+0x70]",
    "mov r15,[rcx+0x78]",
    "mov rcx,[rcx+0x8]",
    ".balign 0x40, 0x90",
    "execute_handler_instruction_base:",
    "nop",
    ".balign 0x40, 0x90",
    "movq xmm1,rax",
    "movq rax,xmm0",
    "movq xmm0,rcx",
    "mov rcx,[rax]",
    "lea rcx,[rcx+0x78]",
    "movq [rcx],xmm1",
    "movq [rcx+0x8],xmm0",
    "mov [rcx+0x10],rdx",
    "mov [rcx+0x18],rbx",
    "mov [rcx+0x20],rsp",
    "mov [rcx+0x28],rbp",
    "mov [rcx+0x30],rsi",
    "mov [rcx+0x38],rdi",
    "mov [rcx+0x40],r8",
    "mov [rcx+0x48],r9",
    "mov [rcx+0x50],r10",
    "mov [rcx+0x58],r11",
    "mov [rcx+0x60],r12",
    "mov [rcx+0x68],r13",
    "mov [rcx+0x70],r14",
    "mov [rcx+0x78],r15",
    "mov rbx,[rax+0x8]",
    "mov rbp,[rax+0x10]",
    "mov rsi,[rax+0x18]",
    "mov rdi,[rax+0x20]",
    "mov r12,[rax+0x28]",
    "mov r13,[rax+0x30]",
    "mov r14,[rax+0x38]",
    "mov r15,[rax+0x40]",
    "mov rsp,rax",
    "pushf",
    "pop rax",
    "mov [rcx-0x34],eax",
    "add rsp,0x68",
    "ret",
    "execute_handler_prototype_end:",
);
