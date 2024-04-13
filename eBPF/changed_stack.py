from __future__ import print_function
from bcc import BPF
from bcc.utils import printb


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(packet_cnt, u64, long, 256);

int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 pass_value = 0;
    long initial_count = 0;
    long *count = &initial_count;
    long one = 1;

    // pull in details
    struct sock *sk = skb->sk;
    u32 saddr = sk->__sk_common.skc_rcv_saddr;
    u32 daddr = sk->__sk_common.skc_daddr;
    u16 sport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;

    pass_value = saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + daddr;

    count = packet_cnt.lookup(&pass_value); 
    if (count)  // check if this map exists
        *count += 1;
    else        // if the map for the key doesn't exist, create one
        {
            packet_cnt.update(&pass_value, &one);
        }

    // output
    if (count) {
    bpf_trace_printk("trace_tcp4connect %x %x %ld\\n", saddr, daddr, *count);
} else {
    bpf_trace_printk("trace_tcp4connect %x %x %ld\\n", saddr, daddr, one);
}

    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-6s %-12s %-16s %-16s %-4s" % ("PID", "COMM", "SADDR", "DADDR", "COUNT"))

def inet_ntoa(addr):
    dq = b''
    for i in range(0, 4):
        dq = dq + str(addr & 0xff).encode()
        if (i != 3):
            dq = dq + b'.'
        addr = addr >> 8
    return dq

# filter and format output
while True:
    # Read messages from the kernel pipe
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (_tag, saddr_hs, daddr_hs, count) = msg.split(b" ")
    except ValueError:
        # Ignore messages from other tracers
        continue
    except KeyboardInterrupt:
        exit()

    # Ignore messages from other tracers
    if _tag.decode() != "trace_tcp4connect":
        continue

    # Print the tracing information
    printb(b"%-6d %-12.12s %-16s %-16s %-4s" % (pid, task, 
        inet_ntoa(int(saddr_hs, 16)),
        inet_ntoa(int(daddr_hs, 16)), count))