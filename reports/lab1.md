# 作业

## 题目

获取任务信息

ch3 中，我们的系统已经能够支持多个任务分时轮流运行，我们希望引入一个新的系统调用 sys_task_info 以获取当前任务的信息，定义如下：

```c++ 
fn sys_task_info(ti: *mut TaskInfo) -> isize;
```

syscall ID: 410

查询当前正在执行的任务信息，任务信息包括任务控制块相关信息（任务状态）、任务使用的系统调用及调用次数、系统调用时刻距离任务第一次被调度时刻的时长（单位ms）。

## 思路

系统调用获取当前正在运行的任务的TaskInfo, 类似于xv6当中的myproc()调用。

通过TaskManager来获取当前正在运行的任务，然后填充这一部分的信息。

具体流程：

1. TaskManager中的inner包含了所有的tasks和正在运行的current_task，通过这里获得当前运行任务。

2. status赋值，syscall_num赋值

这里，syscall_num需要新开一个数组，在TaskControlBlock之中，\[u32;MAX_SYSCALL_NUM\];

需要实现syscall_num，需要给每一个系统调用自增，因此需要给TaskManager实现一个increase_syscall的函数，接受一个syscall_id : usize，给TaskControlBlock自增。


## 注意

syscall中的时间调用应该返回get_time_ms()而不是原始时间。

# 简答作业

## 1 

### ch2b_bad_address.rs

ch2b_bad_address.rs中访问0x0并且进行写操作会导致Page Fault。

0x0是未映射的内存区域，没有关联到任何物理页，因此会导致Page Fault。

如果该代码运行在用户态，那么尝试访问 0x0 会立即导致操作系统抛出 Page Fault，因为用户态程序无权访问此地址。即使在内核态，如果该地址未被映射（如没有正确初始化页表），也会触发 Page Fault。操作系统需要显式映射地址空间，才能进行合法的读写。

### ch2b_bad_instructions.rs 

会发生IllegalInstruction。

sret是RISC-V架构的一条特权指令，用于从S态返回U态。

只有在 S态下才能合法执行 sret 指令。当前状态为U态，因此无法执行，因为权限不足。

### ch2b_bad_register.rs 

发生IllegalInstruction。

csrr用于从控制状态寄存器读取数据，status是一个特权寄存器，只能在S态下访问，如果在用户态下访问就会触发异常。

## 2

### 1

a0代表了sp的值，也就是当前的内核态指针。

__restore用于：1.从用户态陷入内核态，处理系统调用或者恢复上下文。2.内核态中处理异常后恢复之前的上下文。

### 2

sstatus、sepc 和 sscratch。

sstatus用于存储当前的信息，spec用来存储程序计数器的地址，sscratch保存用户栈指针，用于正确切换用户栈。

### 3

x2对应的是sp，恢复上下文时需要保证状态正正确以便于从内核栈切换到用户栈，恢复过程在__alltraps中分配了新的内核栈。

x4对应的是tp,用于保存线程指针，应用程序并不使用这个指针因此可以跳过。

### 4

csrrw将特定的CSR与一个通用寄存器的值进行交换，在这条指令执行之后，sp被更新为原来存储在sscratch中的值，切换到用户栈。

sscratch则交换为内核栈指针的值，此时，sscratch仍然保留着用户栈的地址信息。

### 5

sret。sret使用S态向U态切换的指令，处理器会根据保存在sstatus, sepc, sscratch中的值进行切换。

__restore中，执行csrw恢复了sstatus, sepc, sscratch的值，sstatus中的特定位决定处理器的执行模式。

sepc中存的是用户程序恢复时的执行地址，处理器将在这个地址继续执行。

sret执行后，处理器会读取sstatus的状态信息，根据设置的模式进行切换。如果状态信息指示进入用户态，处理器就切换到用户模式，执行sepc指定的地址处的指令。

### 6

sp被更新为原本的sscratch中的值，也就是栈指针指向用户栈，sscratch保存的是原本的sp的值，保留切换之前的内核栈信息。

### 7 

在执行了csrrw sp, sscratch, sp之后用户态触发了陷入内核态的操作，也就是调用 __alltraps 时就触发了切换。




1. 在完成本次实验的过程（含此前学习的过程）中，我曾分别与 以下各位 就（与本次实验相关的）以下方面做过交流，还在代码中对应的位置以注释形式记录了具体的交流对象及内容：

无。

2.  此外，我也参考了 以下资料 ，还在代码中对应的位置以注释形式记录了具体的参考来源及内容：

[寄存器信息](https://tclin914.github.io/77838749/)

[sret, ret, mret](https://blog.csdn.net/weixin_42031299/article/details/136844715)

3. 我独立完成了本次实验除以上方面之外的所有工作，包括代码与文档。 我清楚地知道，从以上方面获得的信息在一定程度上降低了实验难度，可能会影响起评分。

4. 我从未使用过他人的代码，不管是原封不动地复制，还是经过了某些等价转换。 我未曾也不会向他人（含此后各届同学）复制或公开我的实验代码，我有义务妥善保管好它们。 我提交至本实验的评测系统的代码，均无意于破坏或妨碍任何计算机系统的正常运转。 我清楚地知道，以上情况均为本课程纪律所禁止，若违反，对应的实验成绩将按“-100”分计。
