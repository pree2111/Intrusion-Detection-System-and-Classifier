from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/ip.h>
#include <bcc/proto.h>

BPF_HASH(start, u64, u64);

int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pass_value = 0;
    u32 saddr, daddr;

    struct iphdr *ip_header = (struct iphdr *)(skb->data);
    saddr = ip_header->saddr;
    daddr = ip_header->daddr;

    pass_value = saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + daddr;

    start.update(&pass_value, &ts);

    return 0;
}

int kprobe__ip_local_deliver(struct pt_regs *ctx, struct sk_buff *skb)
{
    u64 *tsp, delta;
    u64 ts = bpf_ktime_get_ns();
    u64 pass_value = 0;
    u32 saddr, daddr;

    struct iphdr *ip_header = (struct iphdr *)(skb->data);
    saddr = ip_header->saddr;
    daddr = ip_header->daddr;

    pass_value = saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + daddr;

    tsp = start.lookup(&pass_value);
    if (tsp != 0) {
        delta = ts - *tsp;
        start.delete(&pass_value);
        bpf_trace_printk("trace_ip_local_deliver %x %x %llu\\n", saddr, daddr, delta);
    }

    return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-16s %-16s %-12s" % ("SADDR", "DADDR", "DELTA"))

def inet_ntoa(addr):
    return '.'.join(str((addr >> i) & 0xff) for i in (0, 8, 16, 24))
# filter and format output
while True:
    # Read messages from the kernel pipe
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (_tag, saddr_hs, daddr_hs, delta) = msg.split(b" ")
    except ValueError:
        # Ignore messages from other tracers
        continue
    except KeyboardInterrupt:
        exit()

    # Ignore messages from other tracers
    if _tag.decode() != "trace_ip_local_deliver":
        continue

    # Print the tracing information
    printb(b"%-16s %-16s %-12s" % (
        inet_ntoa(int(saddr_hs, 16)).encode(),
        inet_ntoa(int(daddr_hs, 16)).encode(), delta))