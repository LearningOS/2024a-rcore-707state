use core::sync::atomic::{AtomicBool, Ordering};

use lazy_static::lazy_static;

use super::{Mutex, UPSafeCell};
/// 自旋锁实现
#[allow(unused)]
pub struct SpinLock {
    locked: AtomicBool,
}
impl SpinLock {
    /// 创建自旋锁
    pub const fn new() -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
        }
    }
}
impl Mutex for SpinLock {
    fn lock(&self) {
        while self.locked.swap(true, Ordering::Acquire) {}
    }
    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}
const MAX_THREADS: usize = 64;
const MAX_RESOURCES: usize = 8;

// 死锁检测数据结构
#[allow(unused)]
pub struct DeadlockDetector {
    enabled: bool,
    available: [usize; MAX_RESOURCES],
    allocation: [[usize; MAX_RESOURCES]; MAX_THREADS],
    need: [[usize; MAX_RESOURCES]; MAX_THREADS],
    pub spinlock: SpinLock,
}

impl DeadlockDetector {
    pub const fn new() -> Self {
        DeadlockDetector {
            enabled: false,
            available: [0; MAX_RESOURCES],
            allocation: [[0; MAX_RESOURCES]; MAX_THREADS],
            need: [[0; MAX_RESOURCES]; MAX_THREADS],
            spinlock: SpinLock::new(),
        }
    }
    #[allow(unused)]
    pub fn enable(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
    // 请求资源
    #[allow(unused)]
    pub fn request_resource(
        &mut self,
        thread_id: usize,
        resource_id: usize,
        amount: usize,
    ) -> isize {
        if !self.enabled {
            return 0; // 如果未启用死锁检测，直接允许资源请求
        }

        // 检查请求的资源数量是否超过可用数量
        if self.available[resource_id] < amount || self.need[thread_id][resource_id] < amount {
            return -0xDEAD;
        }

        // 模拟资源分配，进行死锁检测
        let mut work = self.available;
        let mut finish = [false; MAX_THREADS];

        work[resource_id] -= amount;
        self.allocation[thread_id][resource_id] += amount;
        self.need[thread_id][resource_id] -= amount;

        if self.detect_deadlock(&mut work, &mut finish) {
            // 回滚分配
            self.allocation[thread_id][resource_id] -= amount;
            self.need[thread_id][resource_id] += amount;
            return -0xDEAD;
        }

        // 更新实际资源
        self.available[resource_id] -= amount;
        0
    }

    // 检测死锁
    fn detect_deadlock(
        &self,
        work: &mut [usize; MAX_RESOURCES],
        finish: &mut [bool; MAX_THREADS],
    ) -> bool {
        loop {
            let mut found = false;
            for i in 0..MAX_THREADS {
                if !finish[i] && self.can_finish(i, work) {
                    // 线程 i 可以完成，释放资源
                    for j in 0..MAX_RESOURCES {
                        work[j] += self.allocation[i][j];
                    }
                    finish[i] = true;
                    found = true;
                }
            }

            if !found {
                break;
            }
        }

        // 如果所有线程都能完成，则返回系统安全
        finish.iter().any(|&f| !f)
    }

    fn can_finish(&self, thread_id: usize, work: &[usize; MAX_RESOURCES]) -> bool {
        for j in 0..MAX_RESOURCES {
            if self.need[thread_id][j] > work[j] {
                return false;
            }
        }
        true
    }
}
lazy_static! {
    /// 创建全局资源管理
    pub static ref DEADLOCK_MANAGER: UPSafeCell<DeadlockDetector> =
        unsafe { UPSafeCell::new(DeadlockDetector::new()) };
}
