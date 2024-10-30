//! Process management syscalls

use crate::config::PAGE_SIZE;
use crate::mm::memory_set::{MapArea, MapType};
use crate::mm::MapPermission;
use crate::syscall::{SYSCALL_EXIT, SYSCALL_MMAP, SYSCALL_MUNMAP, SYSCALL_YIELD};
use crate::task::increase_syscall;
use crate::timer::get_time_ms;

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
        syscall_times: current_task.sys_call_times,
        time: get_time_ms(),
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
/// 有bug
/// 2024-10-29 : 目前发现一个问题就是mmap(start,
/// size)时，比如说从0x1000页面开始分配一个页面，也就是0x1000-0x1001,
/// 会存为左闭右闭区间，虽然内存分配是左闭右开，但是存储貌似有问题
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    increase_syscall(SYSCALL_MMAP);
    // 检查 start 是否是页对齐的
    if start % PAGE_SIZE != 0 {
        println!("Page start not right!");
        return -1;
    }
    // 检查 port 是否是有效的
    if port & !0b111 != 0 || port == 0 {
        println!("Wrong mode");
        return -1;
    }
    // 计算虚拟地址范围
    let start_va = VirtAddr::from(start);
    let end_va = VirtAddr::from(start + len);
    let start_vpn = start_va.floor();
    let end_vpn = end_va.ceil();
    // 获取当前任务的页表
    let _page_table = PageTable::from_token(current_user_token());
    // 检查虚拟地址是否对齐
    if !start_va.aligned() {
        println!("Not aligned");
        return -1;
    }
    // 设置映射权限
    let mut flags = MapPermission::from_bits_truncate((port as u8) << 1);
    flags.insert(MapPermission::U);
    // 获取当前任务的内存集
    let inner = &mut TASK_MANAGER.inner.exclusive_access();
    let current_task_id = inner.current_task.clone();
    let current_task = &mut inner.tasks[current_task_id];
    let memory_set = &mut current_task.memory_set;
    // 创建新的 MapArea
    let map_area = MapArea::new(start_vpn.into(), end_vpn.into(), MapType::Framed, flags);
    // 检查映射区域是否已经存在
    // 2024-10-30 理解错find_pte的作用了，所以前面找find_pte的操作是错误的
    for i in map_area.vpn_range {
        if memory_set
            .areas
            .iter()
            .any(|area| area.data_frames.keys().any(|k| k.0 == i.0))
        {
            println!("Already have one btree map key at {}", i);
            return -1;
        }
    }
    // 将新的 MapArea 添加到内存集中
    memory_set.push(map_area, None);
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    increase_syscall(SYSCALL_MUNMAP);
    if start % PAGE_SIZE != 0 {
        println!("not aligned!");
        return -1;
    }
    if len <= 0 {
        println!("Unmap size not right!");
        return -1;
    }
    //计算起始地址到终止地址
    let start_va = VirtAddr::from(start);
    let end_va = VirtAddr::from(start + len);
    let start_vpn = start_va.floor();
    let end_vpn = end_va.ceil();
    // 获取当前任务的页表
    let mut page_table = PageTable::from_token(current_user_token());
    // 获取当前任务的内存集
    let inner = &mut TASK_MANAGER.inner.exclusive_access();
    let current_task_id = inner.current_task.clone();
    let current_task = &mut inner.tasks[current_task_id];
    let memory_set = &mut current_task.memory_set;
    for area in memory_set.areas.iter_mut() {
        if area.vpn_range.get_start() == start_vpn {
            if area.vpn_range.get_end() == end_vpn {
                println!(
                    "Trying to munmap at: {} to {}",
                    area.vpn_range.get_start(),
                    area.vpn_range.get_end()
                );
                area.unmap(&mut page_table);
                return 0;
            } else if area.vpn_range.get_end() > end_vpn {
                println!("Error in munmap: You're unmapping page partially!!!");
                return -1;
            } else {
                println!("Error in munmap: You're unmapping page larger than allocated size!!!");
                return -1;
            }
        }
    }
    0
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
