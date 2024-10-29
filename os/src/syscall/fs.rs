//! File and filesystem-related syscalls

use crate::mm::translated_byte_buffer;
use crate::syscall::SYSCALL_WRITE;
use crate::task::{current_user_token, increase_syscall};

const FD_STDOUT: usize = 1;

/// write buf of length `len`  to a file with `fd`
/// fd文件描述符，buf表示一个内存区间区域，len表示内存区间长度
pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    trace!("kernel: sys_write");
    increase_syscall(SYSCALL_WRITE);
    trace!("increased syscall: SYSCALL_WRITE");
    match fd {
        FD_STDOUT => {
            let buffers = translated_byte_buffer(current_user_token(), buf, len);
            for buffer in buffers {
                print!("{}", core::str::from_utf8(buffer).unwrap());
            }
            len as isize
        }
        _ => {
            panic!("Unsupported fd in sys_write!");
        }
    }
}
