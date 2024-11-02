//! Process management syscalls
use alloc::sync::Arc;

use super::{
    SYSCALL_FORK, SYSCALL_GETPID, SYSCALL_GET_TIME, SYSCALL_MMAP, SYSCALL_MUNMAP, SYSCALL_SBRK,
    SYSCALL_SPAWN, SYSCALL_TASK_INFO, SYSCALL_WAITPID, SYSCALL_YIELD,
};
use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE},
    loader::get_app_data_by_name,
    mm::{
        memory_set::{MapArea, MapType},
        page_table::PageTable,
        translated_refmut, translated_str, MapPermission, VirtAddr,
    },
    syscall::{SYSCALL_EXEC, SYSCALL_EXIT},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        increase_syscall_times, suspend_current_and_run_next, TaskStatus,
    },
    timer::{get_time, get_time_ms},
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
pub fn sys_exit(exit_code: i32) -> ! {
    increase_syscall_times(SYSCALL_EXIT);
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    increase_syscall_times(SYSCALL_YIELD);
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    increase_syscall_times(SYSCALL_GETPID);
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}
/// sys_fork fork对应的系统调用, 返回fork产生的子进程的pid
pub fn sys_fork() -> isize {
    increase_syscall_times(SYSCALL_FORK);
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    // 关键操作
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    increase_syscall_times(SYSCALL_EXEC);
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    increase_syscall_times(SYSCALL_WAITPID);
    trace!(
        "kernel::pid[{}] sys_waitpid [{}]",
        current_task().unwrap().pid.0,
        pid
    );
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    increase_syscall_times(SYSCALL_GET_TIME);
    trace!(
        "kernel:pid[{}] sys_get_time NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    let page_table = PageTable::from_token(current_user_token());
    let current_time = get_time();
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
    increase_syscall_times(SYSCALL_TASK_INFO);
    trace!(
        "kernel:pid[{}] sys_task_info NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    let page_table = PageTable::from_token(current_user_token());
    let task = current_task().unwrap();
    let current_task = task.inner_exclusive_access();
    let task_info = TaskInfo {
        status: current_task.task_status,
        syscall_times: current_task.syscall_times,
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

    -1
}

/// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    increase_syscall_times(SYSCALL_MMAP);
    trace!(
        "kernel:pid[{}] sys_mmap NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
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
    let task = current_task().unwrap();
    let mut current_task = task.inner_exclusive_access();
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
            return -1;
        }
    }
    // 将新的 MapArea 添加到内存集中
    memory_set.push(map_area, None);
    0 - 1
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    increase_syscall_times(SYSCALL_MUNMAP);
    trace!(
        "kernel:pid[{}] sys_munmap NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
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
    let task = current_task().unwrap();
    let mut current_task = task.inner_exclusive_access();
    let memory_set = &mut current_task.memory_set;
    for area in memory_set.areas.iter_mut() {
        if area.vpn_range.get_start() == start_vpn {
            if area.vpn_range.get_end() == end_vpn {
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
    increase_syscall_times(SYSCALL_SBRK);
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(path: *const u8) -> isize {
    increase_syscall_times(SYSCALL_SPAWN);
    trace!(
        "kernel:pid[{}] sys_spawn NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    let parent_task = current_task().unwrap();
    let child_task = parent_task.vfork();
    if Arc::ptr_eq(&current_task().unwrap(), &child_task) {
        let token = current_user_token();
        let path_str = translated_str(token, path);
        if let Some(data) = get_app_data_by_name(path_str.as_str()) {
            child_task.exec(data);
            0
        } else {
            -1
        }
    } else {
        -1
    }
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(_prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    -1
}
