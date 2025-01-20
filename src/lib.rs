#![cfg(target_arch = "x86_64")]

pub mod common;
pub use common::TracePtr;

#[cfg(target_os = "windows")]
pub mod win32;
#[cfg(target_os = "windows")]
pub use win32::context::GetRegistersCONTEXT;
