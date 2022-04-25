/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8 for more details
 */
#include <linux/types.h>
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef __u64 u64;


char LICENSE[] SEC("license") = "Dual BSD/GPL";

// BPF_PERF_OUTPUT(gotopia)

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");
// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/sys_execve")
// SEC("raw_tracepoint/sys_enter")
int hello(void *ctx)
{
    // bpf_printk("Hellp welcome bpf");

    char data[30];
    bpf_get_current_comm(&data, sizeof(data));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}
