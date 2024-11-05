//! File and filesystem-related syscalls

use crate::fs::inode::ROOT_INODE;
use crate::fs::{open_file, OpenFlags, Stat};
use crate::mm::{translated_byte_buffer, translated_str, PageTable, UserBuffer, VirtAddr};
use crate::task::processor::increase_syscall_times;
use crate::task::{current_task, current_user_token};

use super::{
    SYSCALL_CLOSE, SYSCALL_FSTAT, SYSCALL_LINKAT, SYSCALL_OPEN, SYSCALL_READ, SYSCALL_UNLINKAT,
    SYSCALL_WRITE,
};

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    increase_syscall_times(SYSCALL_WRITE);
    trace!("kernel:pid[{}] sys_write", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        if !file.writable() {
            return -1;
        }
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.write(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    increase_syscall_times(SYSCALL_READ);
    trace!("kernel:pid[{}] sys_read", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        if !file.readable() {
            return -1;
        }
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        trace!("kernel: sys_read .. file.read");
        file.read(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    increase_syscall_times(SYSCALL_OPEN);
    trace!("kernel:pid[{}] sys_open", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(inode) = open_file(path.as_str(), OpenFlags::from_bits(flags).unwrap()) {
        let mut inner = task.inner_exclusive_access();
        let fd = inner.alloc_fd();
        inner.fd_table[fd] = Some(inode);
        fd as isize
    } else {
        -1
    }
}

pub fn sys_close(fd: usize) -> isize {
    increase_syscall_times(SYSCALL_CLOSE);
    trace!("kernel:pid[{}] sys_close", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    inner.fd_table[fd].take();
    0
}

/// 2024-11-04 尝试实现fstat
/// YOUR JOB: Implement fstat.
pub fn sys_fstat(_fd: usize, _st: *mut Stat) -> isize {
    increase_syscall_times(SYSCALL_FSTAT);
    let task = current_task().unwrap();
    let inode_file;
    {
        let inner = task.inner_exclusive_access();
        if _fd >= inner.fd_table.len() {
            println!("fd too big: {}", _fd);
            return -1;
        }
        inode_file = match &inner.fd_table[_fd] {
            Some(file) => file.stat(),
            None => {
                return -1;
            }
        };
    }
    let stat_bytes = unsafe {
        core::slice::from_raw_parts(
            &inode_file as *const _ as *const u8,
            core::mem::size_of::<Stat>(),
        )
    };
    let page_table = PageTable::from_token(current_user_token());
    let mut addr = _st as usize;
    for chunk in stat_bytes.chunks(4096) {
        let vpn = VirtAddr::from(addr).floor();
        let offset = VirtAddr::from(addr).page_offset();
        let pte = match page_table.translate(vpn) {
            Some(pte) if pte.is_valid() => pte,
            _ => return -1,
        };
        let ppn = pte.ppn();
        let target_bytes = ppn.get_bytes_array();
        let write_len = (target_bytes.len() - offset).min(chunk.len());
        for i in 0..write_len {
            unsafe {
                core::ptr::write_volatile(target_bytes.as_mut_ptr().add(offset + i), chunk[i]);
            }
        }
        addr += write_len;
    }
    0
}

/// YOUR JOB: Implement linkat.
/// 2024-11-04 尝试实现linkat syscall
pub fn sys_linkat(_old_name: *const u8, _new_name: *const u8) -> isize {
    increase_syscall_times(SYSCALL_LINKAT);
    trace!("kernel:pid[{}] sys_linkat", current_task().unwrap().pid.0);
    let token = current_user_token();
    let old_name = translated_str(token, _old_name);
    let new_name = translated_str(token, _new_name);
    let old_inode = match ROOT_INODE.find(&old_name) {
        Some(inode) => inode,
        None => {
            println!("There is no such file: {}", old_name);
            return -1;
        }
    };
    if ROOT_INODE.find(&new_name).is_some() {
        return -1;
    }
    if ROOT_INODE.link(&new_name, &old_inode) == 1 {
        println!("Successfully linked");
        return 0;
    }
    // match ROOT_INODE.
    -1
}
/// 2024-11-04 尝试实现unlinkat
/// YOUR JOB: Implement unlinkat.
pub fn sys_unlinkat(_name: *const u8) -> isize {
    increase_syscall_times(SYSCALL_UNLINKAT);
    trace!("kernel:pid[{}] sys_unlinkat", current_task().unwrap().pid.0);
    let path = translated_str(current_user_token(), _name);
    let inode = match ROOT_INODE.find(path.as_str()) {
        Some(id) => id,
        None => return -1,
    };
    inode.modify_disk_inode(|disk_inode| {
        if disk_inode.link_count > 0 {
            disk_inode.link_count -= 1;
        }
    });
    let link_count = inode.read_disk_inode(|disk_inode| disk_inode.link_count);
    if link_count == 0 {
        inode.clear();
    }
    -1
}
