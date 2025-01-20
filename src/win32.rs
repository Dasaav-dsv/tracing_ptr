pub mod context;
mod handler;
mod named_mmap;
pub mod tracing;
mod tracing_manager;

#[cfg(test)]
mod tests_win32 {
    use std::{
        mem,
        ptr::{self, NonNull},
        sync::{Arc, Mutex},
    };

    use super::*;
    use crate::TracePtr;
    use tracing::TraceError;

    #[test]
    fn test_trace_null() {
        assert_eq!(
            (&mut ptr::null_mut::<()>()).try_trace(|_| {}),
            Err(TraceError::TriedTracingNull)
        )
    }

    #[test]
    fn test_trace_twice() {
        let mut ptr = ptr::dangling::<u8>();

        ptr.try_trace(|_| {}).unwrap();
        assert_eq!(ptr.try_trace(|_| {}), Err(TraceError::AlreadyTraced));

        unsafe {
            ptr.stop_trace().unwrap();
            assert_eq!(ptr.stop_trace(), Err(TraceError::WasNotTraced));
        }
    }

    #[test]
    fn test_trace() {
        let mut x = [0, 1];
        let mut ptr = NonNull::from(&mut x).cast::<i32>();

        ptr.try_trace(|c| assert_ne!(c.traced_addr, c.accessed_addr))
            .unwrap();

        unsafe {
            ptr.cast::<i32>().offset(1).write(0);

            ptr.stop_trace().unwrap();

            ptr.cast::<i32>().write(1);
        }
    }

    #[test]
    fn test_trace_mut() {
        let mut x = 4;
        let mut ptr = NonNull::from(&mut x);

        let mut values = vec![15, 8, 4];

        ptr.try_trace_mut(move |c| {
            assert_eq!(
                unsafe { ptr::with_exposed_provenance::<i32>(c.accessed_addr.get()).read() },
                values.pop().unwrap()
            )
        })
        .unwrap();

        unsafe {
            ptr.write(8);
            ptr.write(15);
            ptr.write(16);

            ptr.stop_trace().unwrap();

            ptr.write(23);
        }
    }

    #[test]
    fn test_trace_remove() {
        let mut x = 1;
        let mut y = 2;

        let mut ptr_x = NonNull::from(&mut x);
        let mut ptr_y = NonNull::from(&mut y);

        let old_y = Arc::new(Mutex::new(0));

        ptr_x.try_trace(|_| panic!()).unwrap();
        ptr_y
            .try_trace({
                let old_y = old_y.clone();
                move |c| {
                    *old_y.lock().unwrap() =
                        unsafe { ptr::with_exposed_provenance::<i32>(c.accessed_addr.get()).read() }
                }
            })
            .unwrap();

        unsafe {
            ptr_x.stop_trace().unwrap();
        }

        unsafe {
            ptr_y.write(3);

            ptr_y.stop_trace().unwrap();
        }

        assert_eq!(*old_y.lock().unwrap(), 2);
    }

    #[test]
    fn test_trace_call() {
        fn square(x: i32) -> i32 {
            x * x
        }

        let mut ptr = square as *const ();

        ptr.try_trace(|c| unsafe {
            assert_eq!(
                (mem::transmute::<_, fn(i32) -> i32>(ptr::with_exposed_provenance::<()>(
                    c.accessed_addr.get()
                )))(4),
                16
            )
        })
        .unwrap();

        unsafe {
            assert_eq!(mem::transmute::<_, fn(i32) -> i32>(ptr)(3), 9);

            ptr.stop_trace().unwrap();
        }
    }

    #[test]
    fn test_too_many() {
        let x = 0;
        let mut ptr = NonNull::from(&x);

        let mut all = vec![];

        loop {
            let mut ptr_clone = ptr.clone();

            match ptr_clone.try_trace(|_| {}) {
                Ok(()) => all.push(ptr_clone),
                Err(TraceError::TooManyTracers) => break,
                Err(err) => panic!("{:?}", err),
            }
        }

        assert_eq!(ptr.try_trace(|_| {}), Err(TraceError::TooManyTracers));

        unsafe {
            all.pop().unwrap().stop_trace().unwrap();

            ptr.try_trace(|_| {}).unwrap();

            all.iter_mut().try_for_each(|p| p.stop_trace()).unwrap();

            ptr.stop_trace().unwrap();
        }
    }
}
