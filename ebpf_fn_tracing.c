#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/slab.h>

#define MAX_STACK_DEPTH 10

// Define a structure to store information about each function call
struct function_info {
    u64 start_time;
    u64 end_time;
    char function_name[64];
    struct task_struct *task;
    struct stack_trace stack;
};

// Map to store function call information
BPF_HASH(call_info, u64, struct function_info);

// kprobe handler to trace function entry
int trace_function_entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct function_info info = {};

    // Fill in function call information
    info.start_time = bpf_ktime_get_ns();
    info.task = (struct task_struct *)bpf_get_current_task();
    bpf_get_current_comm(&info.task->comm, sizeof(info.task->comm));
    bpf_get_stack_trace(&info.stack, MAX_STACK_DEPTH, BPF_F_USER_STACK);

    // Store function call information in the map
    call_info.update(&pid_tgid, &info);

    return 0;
}

// kretprobe handler to trace function exit
int trace_function_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct function_info *info = call_info.lookup(&pid_tgid);

    if (info) {
        // Fill in more function call information
        info->end_time = bpf_ktime_get_ns();

        // Calculate duration
        u64 duration = info->end_time - info->start_time;

        // Log function call information
        bpf_printk("Function: %s, PID: %d, Duration: %lld ns\n",
                   info->task->comm, bpf_get_current_pid_tgid() >> 32, duration);

        // Print stack trace
        bpf_printk("Stack Trace:\n");
        for (int i = 0; i < info->stack.nr_entries; i++) {
            bpf_printk("    %pS\n", (void *)info->stack.entries[i]);
        }

        // Remove the entry from the map
        call_info.delete(&pid_tgid);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

// Attach the kprobe and kretprobe to specific functions
SEC("kprobe/sys_open")
int kprobe_sys_open(struct pt_regs *ctx) {
    return trace_function_entry(ctx);
}

SEC("kretprobe/sys_open")
int kretprobe_sys_open(struct pt_regs *ctx) {
    return trace_function_exit(ctx);
}

SEC("kprobe/do_sys_open")
int kprobe_do_sys_open(struct pt_regs *ctx) {
    return trace_function_entry(ctx);
}

SEC("kretprobe/do_sys_open")
int kretprobe_do_sys_open(struct pt_regs *ctx) {
    return trace_function_exit(ctx);
}
