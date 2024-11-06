## spawn实现

如果不考虑其他因素，其实spawn类似于vfork+exec。

假定fork采用的是直接复制的策略，那vfork就是采用的阻塞父进程执行、获得父进程地址空间的引用、子进程运行、执行完成、恢复父进程。


## fork 调用

主要部分是调用TaskControlBlock::fork, 返回父进程的TaskControlBlock的拷贝，并分配一个新的Pid。

## Task部分各个结构的关系

###  TaskControlBlock

TaskControlBlock 代表一个任务或进程的控制块，用于存储任务的基本信息和状态。它包含了所有不会在运行时改变的内容，如进程ID (pid) 和内核栈 (kernel_stack)。此外，它还包含一个可变的 inner 字段，该字段封装了实际的任务状态信息：

    pid：任务的唯一标识符。
    kernel_stack：内核栈，用于保存该任务在内核态运行的栈信息。
    inner：包含该任务的动态状态信息，用于存储在运行中可能变化的内容，如内存空间、任务上下文、进程树信息等。

### TaskControlBlockInner

TaskControlBlockInner 是 TaskControlBlock 的内部状态结构体，用于存储运行期间动态变化的内容，如任务的上下文、内存管理、父子关系等。每个 TaskControlBlockInner 都包含以下字段：

    trap_cx_ppn：存储陷入上下文（Trap Context）的物理页号，用于保存用户态的CPU上下文。
    base_size：应用程序的基本大小，用于约束任务在内存中的地址空间。
    task_cx：任务上下文，表示当前任务的 CPU 状态。
    task_status：当前任务的状态（如 Ready、Running、Zombie）。
    memory_set：用于管理该任务的地址空间。
    parent 和 children：当前任务的父子进程关系。
    exit_code：任务退出时的状态码。
    heap_bottom 和 program_brk：用于管理堆内存的范围。

### TaskManager

负责调度所有准备好运行的Task，它维护了一个 ready_queue 队列，包含了所有准备好运行的任务的 TaskControlBlock，从中取出任务并将其交给调度器：

    ready_queue：一个队列，存储处于“Ready”状态的任务。
    add 和 fetch：add 将任务添加到 ready_queue 中，fetch 从队列中取出任务进行调度。


# 荣誉准则


1. 在完成本次实验的过程（含此前学习的过程）中，我曾分别与 以下各位 就（与本次实验相关的）以下方面做过交流，还在代码中对应的位置以注释形式记录了具体的交流对象及内容：

无。

2.  此外，我也参考了 以下资料 ，还在代码中对应的位置以注释形式记录了具体的参考来源及内容：


[寄存器信息](https://tclin914.github.io/77838749/)

[sret, ret, mret](https://blog.csdn.net/weixin_42031299/article/details/136844715)

3. 我独立完成了本次实验除以上方面之外的所有工作，包括代码与文档。 我清楚地知道，从以上方面获得的信息在一定程度上降低了实验难度，可能会影响起评分。

4. 我从未使用过他人的代码，不管是原封不动地复制，还是经过了某些等价转换。 我未曾也不会向他人（含此后各届同学）复制或公开我的实验代码，我有义务妥善保管好它们。 我提交至本实验的评测系统的代码，均无意于破坏或妨碍任何计算机系统的正常运转。 我清楚地知道，以上情况均为本课程纪律所禁止，若违反，对应的实验成绩将按“-100”分计。

 
