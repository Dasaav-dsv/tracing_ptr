use std::{
    arch::x86_64::{__m128, _mm_loadu_ps},
    num::NonZeroUsize,
};

use windows::Win32::System::Diagnostics::Debug::{CONTEXT, M128A};

use iced_x86::{Instruction, InstructionInfo, Register, UsedMemory};

#[derive(Clone)]
pub struct TraceContext<'a> {
    pub traced_addr: NonZeroUsize,
    pub accessed_addr: NonZeroUsize,
    pub instruction: &'a Instruction,
    pub instruction_info: &'a InstructionInfo,
    pub context: &'a CONTEXT,
}

pub(crate) type Tracer =
    dyn for<'a> Fn(&'a Instruction, &'a InstructionInfo, &'a CONTEXT, u64) + Send + Sync;

pub trait GetRegistersCONTEXT {
    fn get_gpr(&self, register: Register) -> Option<u64>;
    fn get_xmm(&self, register: Register) -> Option<__m128>;
    fn get_seg(&self, register: Register) -> Option<u16>;
    fn get_seg_base(register: Register) -> Option<u64>;
    fn get_ip(&self) -> u64;

    fn get_virtual_address(&self, used_memory: &UsedMemory) -> Option<u64>;

    fn get_gpr_mut(&mut self, register: Register) -> Option<&mut u64>;
    fn get_ip_mut(&mut self) -> &mut u64;
}

impl GetRegistersCONTEXT for CONTEXT {
    #[inline]
    fn get_gpr(&self, register: Register) -> Option<u64> {
        const BASE: usize = Register::RAX as usize;
        let index = (register as usize).checked_sub(BASE)?;

        // SAFETY: statically the only exclusive reference into self past this point.
        // This code is performance-critical, yielding a significant speed up for heavy
        // tracing loads compared to a match statement.
        let as_slice = unsafe { std::slice::from_raw_parts(&raw const self.Rax, 16) };

        as_slice.get(index).cloned()
    }

    #[inline]
    fn get_xmm(&self, register: Register) -> Option<__m128> {
        const BASE: usize = Register::XMM0 as usize;
        let index = (register as usize).checked_sub(BASE)?;

        unsafe {
            Some(_mm_loadu_ps(
                self.Anonymous.FltSave.XmmRegisters.get(index)? as *const M128A as _,
            ))
        }
    }

    #[inline]
    fn get_seg(&self, register: Register) -> Option<u16> {
        match register {
            Register::ES => Some(self.SegEs),
            Register::CS => Some(self.SegCs),
            Register::SS => Some(self.SegSs),
            Register::DS => Some(self.SegDs),
            Register::FS => Some(self.SegFs),
            Register::GS => Some(self.SegGs),
            _ => None,
        }
    }

    #[inline]
    fn get_seg_base(register: Register) -> Option<u64> {
        if register == Register::GS {
            let gs_base: u64;
            unsafe {
                std::arch::asm!("mov {}, gs:[0x30]", out(reg) gs_base);
            }
            Some(gs_base)
        } else {
            const BASE: usize = Register::ES as usize;
            let index = (register as usize).checked_sub(BASE)?;
            (index < 5).then_some(0)
        }
    }

    #[inline]
    fn get_ip(&self) -> u64 {
        self.Rip
    }

    #[inline]
    fn get_virtual_address(&self, used_memory: &UsedMemory) -> Option<u64> {
        used_memory.virtual_address(0, |r, _, _| match r.full_register() {
            Register::RIP => Some(self.get_ip()),
            r => self.get_gpr(r).or(CONTEXT::get_seg_base(r)),
        })
    }

    #[inline]
    fn get_gpr_mut(&mut self, register: Register) -> Option<&mut u64> {
        let base = Register::RAX as usize;
        let index = (register as usize).checked_sub(base)?;

        // SAFETY: statically the only exclusive reference into self past this point.
        // This code is performance-critical, yielding a significant speed up for heavy
        // tracing loads compared to a match statement.
        let as_slice = unsafe { std::slice::from_raw_parts_mut(&raw mut self.Rax, 16) };

        as_slice.get_mut(index)
    }

    #[inline]
    fn get_ip_mut(&mut self) -> &mut u64 {
        &mut self.Rip
    }
}

impl std::fmt::Debug for TraceContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceContext")
            .field("traced_addr", &self.traced_addr)
            .field("accessed_addr", &self.accessed_addr)
            .field("instruction", &self.instruction)
            .field("instruction_info", &self.instruction_info)
            .finish_non_exhaustive()
    }
}
