use std::{
    ops::Deref,
    ptr::NonNull,
};

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{FreeLibrary, HMODULE, INVALID_HANDLE_VALUE},
        System::{
            LibraryLoader::{GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS},
            Memory::{CreateFileMappingW, MapViewOfFile, FILE_MAP_ALL_ACCESS, PAGE_READWRITE},
            Threading::{AcquireSRWLockExclusive, ReleaseSRWLockExclusive, SRWLOCK},
        },
    },
};

use windows::core::{Error as WinError, HSTRING as WinString};

#[repr(C)]
pub struct NamedMmap<'a, T: Sync> {
    data: &'a T,
    owner: HMODULE,
    lock: SRWLOCK,
}

unsafe impl<T: Sync> Sync for NamedMmap<'_, T> {}

impl<'a, T: Sync> NamedMmap<'a, T> {
    pub fn new<F>(name: WinString, f: F) -> Result<NamedMmapRef<'a, T>, WinError>
    where
        F: FnOnce() -> T,
    {
        unsafe {
            let handle = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                None,
                PAGE_READWRITE,
                0,
                size_of::<Self>() as u32,
                &name,
            )?;

            let mut mapped = NonNull::new(
                MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, size_of::<Self>()).Value,
            )
            .ok_or(WinError::from_win32())?
            .cast::<Self>();

            // Mapped memory is zero initialized and SRWLock's unlocked state is also zeroed.
            AcquireSRWLockExclusive((&raw mut mapped.as_mut().lock));

            if (&raw mut mapped.as_mut().owner).read().is_invalid() {
                match ref_current_module() {
                    Ok(handle) => {
                        (&raw mut mapped.as_mut().owner).write(handle);
                        (&raw mut mapped.as_mut().data).write(Box::leak(Box::new(f())));
                        
                        ReleaseSRWLockExclusive((&raw mut mapped.as_mut().lock));
                    },
                    Err(err) => {
                        ReleaseSRWLockExclusive((&raw mut mapped.as_mut().lock));

                        return Err(err);
                    }
                }
            } else {
                ReleaseSRWLockExclusive((&raw mut mapped.as_mut().lock));

                mapped.as_ref().ref_owner()?;
            }

            Ok(NamedMmapRef(mapped.as_mut()))
        }
    }

    fn ref_owner(&self) -> Result<(), WinError> {
        // hacky, uses address of the module pseudo-handle
        unsafe {
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                PCWSTR::from_raw(self.owner.0 as *const _),
                &mut HMODULE::default(),
            )?;
        }

        Ok(())
    }

    fn unref_owner(&self) -> Result<(), WinError> {
        unsafe { FreeLibrary(self.owner) }
    }
}

pub fn ref_current_module() -> Result<HMODULE, WinError> {
    let mut handle = HMODULE::default();

    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            PCWSTR::from_raw(ref_current_module as *const _),
            &mut handle,
        )?;
    }

    Ok(handle)
}

impl<'a, T: Sync> Deref for NamedMmap<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

pub struct NamedMmapRef<'a, T: Sync>(&'a NamedMmap<'a, T>);

impl<T: Sync> Drop for NamedMmapRef<'_, T> {
    fn drop(&mut self) {
        let _ = self.0.unref_owner();
    }
}

impl<'a, T: Sync> Deref for NamedMmapRef<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.data
    }
}
