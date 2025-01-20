/// Enables thin tracing for a given pointer.
pub trait TracePtr: Sized {
    /// The type returned in the event of a trace error.
    type Error;

    /// Context that will be passed to the tracer.
    type Context<'a>;

    /// Trace a pointer in place, mutating it.
    /// Exclusively borrowing self allows a tracing implementation
    /// to account for multiple tracers.
    fn try_trace<F>(&mut self, f: F) -> Result<(), Self::Error>
    where
        F: Fn(Self::Context<'_>) + Send + Sync + 'static;

    /// Trace a pointer in place, mutating it.
    /// Exclusively borrowing self allows a tracing implementation
    /// to account for multiple tracers.
    fn try_trace_mut<F>(&mut self, f: F) -> Result<(), Self::Error>
    where
        F: FnMut(Self::Context<'_>) + Send + 'static;

    /// Restore the traced pointer and stop tracing it.
    /// SAFETY: excercise immense caution calling this function.
    /// Any accesses through copies of the traced pointer after
    /// calling `TracePtr::stop_trace` will crash the program.
    unsafe fn stop_trace(&mut self) -> Result<(), Self::Error>;

    /// Is self being traced by any tracer?
    /// Care should be taken to account for multiple competing tracers
    /// running the same implementation.
    fn is_trace_ptr(&self) -> bool;
}
