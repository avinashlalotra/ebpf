#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/syscalls/sys_enter_execve")
// this function will be called whenever exec sys call is called
int test(void *ctx) {
  bpf_printk("EXEC HIT\n");
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
