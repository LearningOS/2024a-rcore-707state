//! Process management syscalls

use crate::config::PAGE_SIZE;
use crate::mm::page_table::PTEFlags;
use crate::mm::{frame_alloc, VirtPageNum};
use crate::syscall::{SYSCALL_EXIT, SYSCALL_MMAP, SYSCALL_MUNMAP, SYSCALL_YIELD};
use crate::task::increase_syscall;
use crate::{
    config::MAX_SYSCALL_NUM,
    mm::{page_table::PageTable, VirtAddr},
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next, TaskStatus, TASK_MANAGER,
    },
    timer::get_time_us,
};

use super::{SYSCALL_GET_TIME, SYSCALL_TASK_INFO};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    increase_syscall(SYSCALL_EXIT);
    trace!("increased syscall: SYSCALL_EXIT");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    increase_syscall(SYSCALL_YIELD);
    trace!("increased syscall: SYSCALL_YIELD");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    increase_syscall(SYSCALL_GET_TIME);
    trace!("increased syscall: SYSCALL_GET_TIME");
    //获取当前进程的token
    trace!("kernel: sys_get_time");
    //获取当前进程的页表
    let token = current_user_token();
    //获得页表(物理)
    let page_table = PageTable::from_token(token);
    //确保指针合法
    let current_time = get_time_us();
    let time_val = TimeVal {
        sec: current_time / 1_000_000,
        usec: current_time % 1_000_000,
    };
    let mut ts_addr = ts as usize;
    let time_val_bytes = unsafe {
        core::slice::from_raw_parts(
            &time_val as *const _ as *const u8,
            core::mem::size_of::<TimeVal>(),
        )
    };
    //遍历这些字节, 逐页写入内存
    for chunk in time_val_bytes.chunks(4096) {
        //为什么要分块，因为TimeVal结构体可能横跨两个页面
        //获取虚拟页号
        let vpn = VirtAddr::from(ts_addr).floor();
        //获取页内偏移
        let page_offset = VirtAddr::from(ts_addr).page_offset();
        //获得有效页表项
        let pte = match page_table.translate(vpn) {
            //确保虚拟页号映射到了一个有效的物理页
            Some(pte) if pte.is_valid() => pte,
            _ => return -1,
        };
        // 获取物理页的字节数组
        let ppn = pte.ppn(); //找到物理页
        let bytes = ppn.get_bytes_array();
        //计算写入的长度
        let write_len = (bytes.len() - page_offset).min(chunk.len());
        //将字节块写入物理页中的对应位置
        for i in 0..write_len {
            unsafe {
                // volatile 写入：表示这是和硬件或内存有关的操作，不允许被优化，否则会导致程序错误
                core::ptr::write_volatile(bytes.as_mut_ptr().add(page_offset + i), chunk[i]);
            }
        }
        //更新地址，处理跨页
        ts_addr += write_len;
    }
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info NOT IMPLEMENTED YET!");
    increase_syscall(SYSCALL_TASK_INFO);
    trace!("increased syscall: SYSCALL_TASK_INFO");
    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    //获取任务控制快
    let inner = TASK_MANAGER.inner.exclusive_access();
    let current_task = &inner.tasks[inner.current_task];
    //TaskInfo转为字节数组
    let task_info = TaskInfo {
        status: current_task.task_status,
        syscall_times: [0; MAX_SYSCALL_NUM],
        time: 0,
    };
    let info_bytes = unsafe {
        core::slice::from_raw_parts(
            &task_info as *const _ as *const u8,
            core::mem::size_of::<TaskInfo>(),
        )
    };
    let mut addr = _ti as usize;
    for chunk in info_bytes.chunks(4096) {
        //计算虚拟页号和业内偏移
        let vpn = VirtAddr::from(addr).floor();
        let offset = VirtAddr::from(addr).page_offset();
        //查找页表项
        let pte = match page_table.translate(vpn) {
            Some(pte) if pte.is_valid() => pte,
            _ => return -1,
        };
        let ppn = pte.ppn();
        let target_bytes = ppn.get_bytes_array();
        //计算可写入的长度
        let write_len = (target_bytes.len() - offset).min(chunk.len());
        //写入物理页的数据
        for i in 0..write_len {
            unsafe {
                core::ptr::write_volatile(target_bytes.as_mut_ptr().add(offset + i), chunk[i]);
            }
        }
        addr += write_len;
    }
    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    increase_syscall(SYSCALL_MMAP);
    trace!("increased syscall: SYSCALL_MMAP");
    //长度无效或者地址地址没有页对齐
    if len == 0 || start % PAGE_SIZE != 0 {
        return -1;
    }
    //计算分配所需的页数
    let num_pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    //获取当前进程的页表
    let token = current_user_token();
    let mut page_table = PageTable::from_token(token);
    //分配物理页并开始映射
    let mut current_start = start;
    for _ in 0..num_pages {
        //当前地址已经被映射
        if page_table
            .find_pte(VirtPageNum::from(current_start))
            .is_some()
        {
            return -1;
        }
        current_start += PAGE_SIZE;
    }
    //为每个虚拟页分配物理页框并建立映射
    current_start = start;
    for _ in 0..num_pages {
        let frame = match frame_alloc() {
            Some(f) => f,
            None => return -1,
        };
        let flags = match port & 0x7 {
            0x1 => PTEFlags::R,
            0x2 => PTEFlags::W,
            0x3 => PTEFlags::R | PTEFlags::W,
            0x4 => PTEFlags::X,
            0x5 => PTEFlags::R | PTEFlags::X,
            0x6 => PTEFlags::X | PTEFlags::W,
            0x7 => PTEFlags::X | PTEFlags::W | PTEFlags::R,
            _ => unreachable!(),
        };
        page_table.map(
            VirtPageNum::from(current_start),
            frame.ppn,
            flags | PTEFlags::V,
        );
        current_start += PAGE_SIZE;
    }
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
    increase_syscall(SYSCALL_MUNMAP);
    //检验起始地址和长度
    if len == 0 || start % PAGE_SIZE != 0 {
        return -1;
    }
    let num_pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    //获取页表
    let token = current_user_token();
    let mut page_table = PageTable::from_token(token);
    //遍历所有页并解除映射
    let mut current_start = start;
    for _ in 0..num_pages {
        //虚拟页面没有被映射
        if let Some(pte) = page_table.find_pte(VirtPageNum::from(current_start)) {
            if !pte.is_valid() {
                return -1;
            }
            page_table.unmap(VirtPageNum::from(current_start));
        } else {
            //当前地址没有被映射
            return -1;
        }
        current_start += PAGE_SIZE;
    }

    -1
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
