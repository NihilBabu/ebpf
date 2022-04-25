// +build ignore
#include "hello.bpf.h"

BPF_PERF_OUTPUT(gotopia)
// SEC("kprobe/sys_execve")
SEC("raw_tracepoint/sys_enter")
int hello(void *ctx)
{
    // bpf_printk("Hellp welcome bpf");

    char data[30];
    bpf_get_current_comm(&data,sizeof(data));
    bpf_perf_event_output(ctx, &gotopia, BPF_F_CURRENT_CPU, &data,sizeof(data));
    return 0;
}