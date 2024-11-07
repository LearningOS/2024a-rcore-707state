use alloc::{collections::VecDeque, vec::Vec};

/// 资源类型
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    /// 互斥量
    Mutex(usize),
    /// 信号量
    Semaphore(usize),
}
// 死锁检测数据结构
/// 这里应该属于一个process而不是一个全局变量
pub struct DeadlockDetector {
    /// 使用资源的类型
    resources: Vec<Option<ResourceType>>,
    //回收资源的id
    recycled: VecDeque<usize>,
    // 当前任务数量
    task_nums: usize,
    // 每个任务最大需求
    max_demand: Vec<Vec<usize>>,
    //每个任务已经分配的资源
    allocated: Vec<Vec<usize>>,
    // 每种资源剩余的数目
    available: Vec<usize>,
    // 需求矩阵
    need: Vec<Vec<usize>>,
}
impl DeadlockDetector {
    /// 新建一个deadlock detector
    pub fn new() -> Self {
        DeadlockDetector {
            resources: Vec::new(),
            recycled: VecDeque::new(),
            task_nums: 1,
            max_demand: alloc::vec![Vec::new()],
            allocated: alloc::vec![Vec::new()],
            available: Vec::new(),
            need: alloc::vec![Vec::new()],
        }
    }
    // 扩充矩阵
    fn extend_matrix(&mut self) {
        self.max_demand.push(alloc::vec![0;self.resources.len()]);
        self.allocated.push(alloc::vec![0;self.resources.len()]);
        self.need.push(alloc::vec![0;self.resources.len()]);
    }
    // 缩减矩阵
    fn reset_task_resources(&mut self, task_id: usize) {
        self.max_demand[task_id].fill(0);
        self.allocated[task_id].fill(0);
        self.need[task_id].fill(0);
    }
    /// 扩展所有任务的资源矩阵
    #[allow(unused)]
    fn extend_all_task_matrices(&mut self) {
        for task in &mut self.max_demand {
            task.push(0);
        }
        for task in &mut self.allocated {
            task.push(0);
        }
        for task in &mut self.need {
            task.push(0);
        }
    }
    /// 检查是否可以满足任务需求
    fn can_satisfy_task(&self, task_id: usize, work: &[usize]) -> bool {
        self.need[task_id]
            .iter()
            .enumerate()
            .all(|(res_id, &need)| need <= work[res_id])
    }

    /// 为任务分配可用资源
    fn allocate_resources(&self, task_id: usize, work: &mut [usize]) {
        for (res_id, alloc) in self.allocated[task_id].iter().enumerate() {
            work[res_id] += alloc;
        }
    }

    /// 回退资源请求
    fn revert_request(&mut self, task_id: usize, resource_id: usize, amount: usize) {
        self.max_demand[task_id][resource_id] -= amount;
        self.need[task_id][resource_id] -= amount;
    }
    /// 获取资源的 ID
    fn resource_id(&self, resource: ResourceType) -> Option<usize> {
        self.resources.iter().position(|res| res == &Some(resource))
    }
    /// 更新任务
    pub fn update_task(&mut self, task_id: usize) -> usize {
        if task_id >= self.task_nums {
            for _ in self.task_nums..=task_id {
                self.extend_matrix();
            }
            self.task_nums = task_id + 1;
            self.task_nums
        } else {
            self.task_nums
        }
    }
    /// 移除一个任务
    pub fn remove_task(&mut self, task_id: usize) -> bool {
        if task_id >= self.task_nums {
            return false;
        }
        self.reset_task_resources(task_id);
        true
    }
    /// 添加新资源
    pub fn add_resource(&mut self, resource: ResourceType, total: usize) {
        if let Some(id) = self.recycled.pop_front() {
            self.resources[id] = Some(resource);
            self.available[id] = total;
            return;
        }
        self.resources.push(Some(resource));
        self.available.push(total);
        self.max_demand.iter_mut().for_each(|task| task.push(0));
        self.allocated.iter_mut().for_each(|task| task.push(0));
        self.need.iter_mut().for_each(|task| task.push(0));

        // let id = if let Some(recycled_id) = self.recycled.pop_front() {
        //     recycled_id
        // } else {
        //     self.resources.len()
        // };

        // self.set_resource(id, resource, total);
        // if id >= self.resources.len() {
        //     self.resources.push(Some(resource));
        // } else {
        //     self.resources[id] = Some(resource);
        // }
    }
    /// 移除资源
    pub fn remove_resource(&mut self, resource: ResourceType) -> bool {
        if let Some(id) = self.resource_id(resource) {
            self.resources[id] = None;
            self.recycled.push_back(id);
            self.available[id] = 0;
            self.max_demand.iter_mut().for_each(|task| task[id] = 0);
            self.allocated.iter_mut().for_each(|task| task[id] = 0);
            self.need.iter_mut().for_each(|task| task[id] = 0);
            true
        } else {
            false
        }
    }
    ///获取成功就返回true, 否则false
    pub fn requesting(&mut self, task_id: usize, resource: ResourceType, amount: usize) -> bool {
        let resource_id = self.resource_id(resource).expect("resource not found");
        self.max_demand[task_id][resource_id] += amount;
        self.need[task_id][resource_id] += amount;
        if self.is_safe() {
            true
        } else {
            self.revert_request(task_id, resource_id, amount);
            false
        }
    }
    /// 分配资源，不进行尝试
    pub fn request_direct(&mut self, task_id: usize, resource: ResourceType, amount: usize) {
        let resource_id = self.resource_id(resource).expect("resource not found");
        self.allocated[task_id][resource_id] += amount;
        self.need[task_id][resource_id] -= amount;
        self.available[resource_id] -= amount;
    }
    /// 释放一个任务的资源
    pub fn release_task(&mut self, task_id: usize, resource: ResourceType, amount: usize) {
        let resource_id = self.resource_id(resource).expect("resource not found");
        self.allocated[task_id][resource_id] -= amount;
        self.max_demand[task_id][resource_id] -= amount;
        self.available[resource_id] += amount;
    }
    /// 判断是否能够安全地分配
    pub fn is_safe(&self) -> bool {
        let mut work = self.available.clone();
        let mut finish = alloc::vec![false;self.task_nums];
        let mut count = 0;
        while count < self.task_nums {
            let mut found = false;
            for task_id in 0..self.task_nums {
                if finish[task_id] || !self.can_satisfy_task(task_id, &work) {
                    continue;
                }
                self.allocate_resources(task_id, &mut work);
                finish[task_id] = true;
                count += 1;
                found = true;
            }
            if !found {
                return false;
            }
        }
        true
    }
}
