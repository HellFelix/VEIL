//! The single sanctioned entry point to libc.

use std::io;

/// A libc return value that signals failure with a negative number.
pub trait Errno: Copy {
    /// Whether this value represents the conventional failure return.
    fn is_failure(self) -> bool;
}

macro_rules! impl_errno {
    ($($t:ty),*) => {
        $(impl Errno for $t {
            fn is_failure(self) -> bool { self < 0 }
        })*
    };
}

impl_errno!(i8, i16, i32, i64, isize);

/// Converts a libc return value into a [`Result`], reading `errno` on failure.
///
/// Not called directly: [`syscall!`](crate::syscall) is the interface.
#[doc(hidden)]
pub fn check<T: Errno>(res: T) -> io::Result<T> {
    if res.is_failure() {
        Err(io::Error::last_os_error())
    } else {
        Ok(res)
    }
}

/// Calls a libc function and converts the conventional `-1` failure into
/// [`io::Error::last_os_error`](std::io::Error::last_os_error).
///
/// This macro is the only permitted way to call libc in this crate. The point
/// is that there is no syntax for discarding the return value: the result is a
/// `io::Result` and the caller must handle it.
///
/// v1's raw sockets failed partly because `socket()`'s result was never
/// compared against `-1` and `setsockopt`'s was bound to an unused variable, so
/// a failed socket surfaced as `EBADF` from an unrelated `sendto` far away.
///
/// Arguments are bound in a safe context before the `unsafe` block, so a caller
/// cannot place unsafe code inside it without writing `unsafe` themselves.
/// Arities up to six are supported, which covers every libc call VEIL makes.
///
/// ```
/// # fn main() -> std::io::Result<()> {
/// let pid = veil_net::syscall!(getpid())?;
/// assert!(pid > 0);
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! syscall {
    ($fn:ident ()) => {
        $crate::check(unsafe { ::libc::$fn() })
    };
    ($fn:ident ($a:expr $(,)?)) => {{
        let a = $a;
        $crate::check(unsafe { ::libc::$fn(a) })
    }};
    ($fn:ident ($a:expr, $b:expr $(,)?)) => {{
        let (a, b) = ($a, $b);
        $crate::check(unsafe { ::libc::$fn(a, b) })
    }};
    ($fn:ident ($a:expr, $b:expr, $c:expr $(,)?)) => {{
        let (a, b, c) = ($a, $b, $c);
        $crate::check(unsafe { ::libc::$fn(a, b, c) })
    }};
    ($fn:ident ($a:expr, $b:expr, $c:expr, $d:expr $(,)?)) => {{
        let (a, b, c, d) = ($a, $b, $c, $d);
        $crate::check(unsafe { ::libc::$fn(a, b, c, d) })
    }};
    ($fn:ident ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr $(,)?)) => {{
        let (a, b, c, d, e) = ($a, $b, $c, $d, $e);
        $crate::check(unsafe { ::libc::$fn(a, b, c, d, e) })
    }};
    ($fn:ident ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr $(,)?)) => {{
        let (a, b, c, d, e, f) = ($a, $b, $c, $d, $e, $f);
        $crate::check(unsafe { ::libc::$fn(a, b, c, d, e, f) })
    }};
}

#[cfg(test)]
mod tests {
    use crate::syscall;

    #[test]
    fn success_yields_the_return_value() {
        let pid = syscall!(getpid()).expect("getpid cannot fail");
        assert!(pid > 0);
    }

    #[test]
    fn failure_yields_the_errno() {
        // Closing a descriptor that was never opened must surface as EBADF
        // rather than being silently discarded.
        let err = syscall!(close(-1)).expect_err("close(-1) must fail");
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn multiple_arguments_reach_the_call_in_order() {
        // dup3(fd, fd, 0) with both descriptors equal is defined to fail with
        // EINVAL, which proves all three arguments arrived where intended.
        let fd = syscall!(dup(0)).expect("stdin can be duplicated");
        let err = syscall!(dup3(fd, fd, 0)).expect_err("dup3 onto itself must fail");
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        syscall!(close(fd)).expect("the duplicate closes");
    }
}
