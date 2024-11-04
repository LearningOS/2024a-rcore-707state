//!Implementation of [`TaskManager`]
use super::TaskControlBlock;
use crate::sync::UPSafeCell;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;
///A array of `TaskControlBlock` that is thread-safe
pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
}

/// A simple FIFO scheduler.
impl TaskManager {
    ///Creat an empty TaskManager
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        self.ready_queue.push_back(task);
    }
    /// Take a process out of the ready queue
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.ready_queue.pop_front()
    }
    /// Stride Scheduling
    pub fn stride_fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        if self.ready_queue.is_empty() {
            return None;
        }
        // Find the task with the minimum stride
        let mut min_stride_task = None;
        let mut min_stride = usize::MAX;
        for task in &self.ready_queue {
            let task_inner = task.inner_exclusive_access();
            if task_inner.stride < min_stride {
                min_stride = task_inner.stride;
                min_stride_task = Some(task.clone());
            }
        }
        // Update the stride of the chosen task
        if let Some(task) = min_stride_task.clone() {
            let mut task_inner = task.inner_exclusive_access();
            task_inner.stride += task_inner.pass;
        }
        // Remove the selected task from the ready queue
        if let Some(task) = &min_stride_task {
            if let Some(pos) = self.ready_queue.iter().position(|x| Arc::ptr_eq(x, task)) {
                self.ready_queue.remove(pos);
            }
        }
        min_stride_task
    }
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

/// Add process to ready queue
pub fn add_task(task: Arc<TaskControlBlock>) {
    //trace!("kernel: TaskManager::add_task");
    TASK_MANAGER.exclusive_access().add(task);
}

/// Take a process out of the ready queue
#[allow(unused)]
pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    //trace!("kernel: TaskManager::fetch_task");
    TASK_MANAGER.exclusive_access().fetch()
}
/// Use stride scheduling fetch method
#[allow(unused)]
pub fn stride_fetch_task() -> Option<Arc<TaskControlBlock>> {
    TASK_MANAGER.exclusive_access().stride_fetch()
}
