use std::{
    num::{NonZero, NonZeroUsize},
    ops::BitAnd,
    ptr::NonNull,
    sync::{Arc, Mutex},
};

use crate::{common::TracePtr, win32::tracing_manager::TRACING_MANAGER};

use super::context::{TraceContext, Tracer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceError {
    WasNotTraced,
    AlreadyTraced,
    TooManyTracers,
    TriedTracingNull,
}

pub(crate) const TRACE_PTR_MASK: usize = 0x0000_7FFF_FFFF_FFFF;
pub(crate) const TRACE_INDEX_MASK: usize = 0xFFFF_8000_0000_0000;

pub(crate) const TRACE_INDEX_MAX: usize = 0x1FFFF;

impl<T> TracePtr for NonNull<T> {
    type Error = TraceError;
    type Context<'a> = TraceContext<'a>;

    #[inline]
    fn try_trace<F>(&mut self, f: F) -> Result<(), Self::Error>
    where
        F: Fn(Self::Context<'_>) + Send + Sync + 'static,
    {
        if self.is_trace_ptr() {
            return Err(TraceError::AlreadyTraced);
        }

        let trace_index = TRACING_MANAGER
            .insert(new_tracer(self.addr(), f))
            .ok_or(TraceError::TooManyTracers)?;

        *self = self.map_addr(|a| a | (trace_index.get() << 47));

        Ok(())
    }

    #[inline]
    fn try_trace_mut<F>(&mut self, f: F) -> Result<(), Self::Error>
    where
        F: FnMut(Self::Context<'_>) + Send + 'static,
    {
        if self.is_trace_ptr() {
            return Err(TraceError::AlreadyTraced);
        }

        let trace_index = TRACING_MANAGER
            .insert(new_tracer_mut(self.addr(), f))
            .ok_or(TraceError::TooManyTracers)?;

        *self = self.map_addr(|a| a | (trace_index.get() << 47));

        Ok(())
    }

    #[inline]
    fn is_trace_ptr(&self) -> bool {
        (self.addr().get() & TRACE_INDEX_MASK) != 0
    }

    #[inline]
    unsafe fn stop_trace(&mut self) -> Result<(), Self::Error> {
        let index = (self.addr().get() >> 47)
            .try_into()
            .map_err(|_| TraceError::WasNotTraced)?;

        *self = self.map_addr(|a| a.get().bitand(TRACE_PTR_MASK).try_into().unwrap());

        unsafe { TRACING_MANAGER.remove(index) };

        Ok(())
    }
}

impl<T> TracePtr for *const T {
    type Error = TraceError;
    type Context<'a> = TraceContext<'a>;

    #[inline]
    fn try_trace<F>(&mut self, f: F) -> Result<(), Self::Error>
    where
        F: Fn(Self::Context<'_>) + Send + Sync + 'static,
    {
        let non_null_addr = NonNull::new(self)
            .ok_or(TraceError::TriedTracingNull)?
            .addr();

        if self.is_trace_ptr() {
            return Err(TraceError::AlreadyTraced);
        }

        let trace_index = TRACING_MANAGER
            .insert(new_tracer(non_null_addr, f))
            .ok_or(TraceError::TooManyTracers)?;

        *self = self.map_addr(|a| a | (trace_index.get() << 47));

        Ok(())
    }

    #[inline]
    fn try_trace_mut<F>(&mut self, f: F) -> Result<(), Self::Error>
    where
        F: FnMut(Self::Context<'_>) + Send + 'static,
    {
        let non_null_addr = NonNull::new(self)
            .ok_or(TraceError::TriedTracingNull)?
            .addr();

        if self.is_trace_ptr() {
            return Err(TraceError::AlreadyTraced);
        }

        let trace_index = TRACING_MANAGER
            .insert(new_tracer_mut(non_null_addr, f))
            .ok_or(TraceError::TooManyTracers)?;

        *self = self.map_addr(|a| a | (trace_index.get() << 47));

        Ok(())
    }

    #[inline]
    fn is_trace_ptr(&self) -> bool {
        (self.addr() & TRACE_INDEX_MASK) != 0
    }

    #[inline]
    unsafe fn stop_trace(&mut self) -> Result<(), Self::Error> {
        let index = (self.addr() >> 47)
            .try_into()
            .map_err(|_| TraceError::WasNotTraced)?;

        *self = self.map_addr(|a| a.bitand(TRACE_PTR_MASK));

        TRACING_MANAGER.remove(index);

        Ok(())
    }
}

impl<T> TracePtr for *mut T {
    type Error = TraceError;
    type Context<'a> = TraceContext<'a>;

    #[inline]
    fn try_trace<F>(&mut self, f: F) -> Result<(), Self::Error>
    where
        F: Fn(Self::Context<'_>) + Send + Sync + 'static,
    {
        let non_null_addr = NonNull::new(self)
            .ok_or(TraceError::TriedTracingNull)?
            .addr();

        if self.is_trace_ptr() {
            return Err(TraceError::AlreadyTraced);
        }

        let trace_index = TRACING_MANAGER
            .insert(new_tracer(non_null_addr, f))
            .ok_or(TraceError::TooManyTracers)?;

        *self = self.map_addr(|a| a | (trace_index.get() << 47));

        Ok(())
    }

    #[inline]
    fn try_trace_mut<F>(&mut self, f: F) -> Result<(), Self::Error>
    where
        F: FnMut(Self::Context<'_>) + Send + 'static,
    {
        let non_null_addr = NonNull::new(self)
            .ok_or(TraceError::TriedTracingNull)?
            .addr();

        if self.is_trace_ptr() {
            return Err(TraceError::AlreadyTraced);
        }

        let trace_index = TRACING_MANAGER
            .insert(new_tracer_mut(non_null_addr, f))
            .ok_or(TraceError::TooManyTracers)?;

        *self = self.map_addr(|a| a | (trace_index.get() << 47));

        Ok(())
    }

    #[inline]
    fn is_trace_ptr(&self) -> bool {
        (self.addr() & TRACE_INDEX_MASK) != 0
    }

    #[inline]
    unsafe fn stop_trace(&mut self) -> Result<(), Self::Error> {
        let index = (self.addr() >> 47)
            .try_into()
            .map_err(|_| TraceError::WasNotTraced)?;

        *self = self.map_addr(|a| a.bitand(TRACE_PTR_MASK));

        TRACING_MANAGER.remove(index);

        Ok(())
    }
}

#[inline]
fn new_tracer<F>(traced_addr: NonZeroUsize, f: F) -> Arc<Tracer>
where
    F: Fn(TraceContext<'_>) + Send + Sync + 'static,
{
    Arc::new(
        move |instruction, instruction_info, context, accessed_addr| {
            f(TraceContext {
                traced_addr,
                accessed_addr: NonZero::try_from(accessed_addr as usize).expect("non-zero address"),
                instruction,
                instruction_info,
                context,
            });
        },
    )
}

#[inline]
fn new_tracer_mut<F>(traced_addr: NonZeroUsize, f: F) -> Arc<Tracer>
where
    F: FnMut(TraceContext<'_>) + Send + 'static,
{
    let mutex = Mutex::new(f);
    Arc::new(
        move |instruction, instruction_info, context, accessed_addr| {
            mutex.lock().unwrap()(TraceContext {
                traced_addr,
                accessed_addr: NonZero::try_from(accessed_addr as usize).expect("non-zero address"),
                instruction,
                instruction_info,
                context,
            });
        },
    )
}
