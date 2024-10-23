//! Process management syscalls

use crate::{
    config::MAX_SYSCALL_NUM,
    mm::{page_table::PageTable, VirtAddr},
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next, TaskStatus,
    },
    timer::get_time_us,
};

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
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    //获取当前进程的token
    // let token=
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
    -1
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    -1
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
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
