use std::{
    cell::UnsafeCell,
    num::NonZeroUsize,
    ops::{Add, Sub},
    sync::{Arc, LazyLock},
};

use crossbeam_queue::ArrayQueue;

use super::{
    handler::add_handler,
    named_mmap::{NamedMmap, NamedMmapRef},
    tracing::TRACE_INDEX_MAX,
    context::Tracer
};

#[repr(C)]
pub struct TracingManager {
    data: boxcar::Vec<UnsafeCell<Option<Arc<Tracer>>>>,
    free_list: ArrayQueue<usize>,
}

unsafe impl Sync for TracingManager {}

impl TracingManager {
    #[inline]
    pub fn get(
        &self,
        trace_index: NonZeroUsize,
    ) -> Option<Arc<Tracer>> {
        unsafe {
            self.data
                .get(trace_index.get().sub(1))?
                .get()
                .as_ref()
                .and_then(|e| e.clone())
        }
    }

    #[inline]
    pub fn insert(&self, tracer: Arc<Tracer>) -> Option<NonZeroUsize> {
        let new_index = if let Some(empty_index) = self.free_list.pop() {
            let empty = self
                .data
                .get(empty_index)
                .expect("free_index is within `Vec` size");

            unsafe {
                *empty.get().as_mut().unwrap() = Some(tracer);
            }

            Some(empty_index)
        } else if self.data.count() < TRACE_INDEX_MAX {
            let new_index = self.data.push(UnsafeCell::new(Some(tracer)));

            (new_index < TRACE_INDEX_MAX).then_some(new_index)
        } else {
            None
        };

        new_index.map(|i| (i.add(1).try_into().unwrap()))
    }

    #[inline]
    pub unsafe fn remove(&self, index: NonZeroUsize) {
        let index = index.get().sub(1);

        if let Some(entry) = self.data.get(index) {
            let _ = unsafe { entry.get().as_mut() }.unwrap().take(); 
            let _ = self.free_list.push(index);
        }
    }
}

pub static TRACING_MANAGER: LazyLock<NamedMmapRef<TracingManager>> = LazyLock::new(|| {
    NamedMmap::new("TRACING_PTR_MANAGER".into(), || {
        add_handler();
        TracingManager {
            data: boxcar::Vec::new(),
            free_list: ArrayQueue::new(TRACE_INDEX_MAX),
        }
    })
    .unwrap()
});
