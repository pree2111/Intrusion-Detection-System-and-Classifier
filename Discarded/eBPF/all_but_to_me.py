from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import socket
import subprocess

def get_ip_address():
    ip_address = subprocess.check_output("ip route get 1 | awk '{print $NF;exit}'", shell=True)
    return ip_address.strip().decode()

# Get the IP address of the machine
my_ip = get_ip_address()
my_ip = sum(int(x) << (i * 8) for i, x in enumerate(my_ip.split(".")[::-1]))

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/ip.h>
#include <bcc/proto.h>

BPF_HASH(packet_cnt, u64, long, 256);

int kprobe__nf_hook_slow(struct pt_regs *ctx, const struct nf_hook_ops *ops, struct sk_buff *skb)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 pass_value = 0;
    long initial_count = 0;
    long *count = &initial_count;
    long one = 1;

    // pull in details
    struct iphdr *ip_header;
    u32 saddr, daddr;

    // Get the IP header
    ip_header = (struct iphdr *)(skb->network_header);

    // Extract source and destination IP addresses from the IP header
    saddr = ip_header->saddr;
    daddr = ip_header->daddr;

    // Ignore packets not destined for our machine
    if (daddr != """ + str(my_ip) + """)
        return 0;

    pass_value = saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + daddr;

    count = packet_cnt.lookup(&pass_value); 
    if (count)  // check if this map exists
        *count += 1;
    else        // if the map for the key doesn't exist, create one
        packet_cnt.update(&pass_value, &one);

    // output
    if (count)
        bpf_trace_printk("trace_nf_hook_slow %x %x %ld\\n", saddr, daddr, *count);
    else
        bpf_trace_printk("trace_nf_hook_slow %x %x %ld\\n", saddr, daddr, one);

    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)

# Header
print("%-6s %-12s %-16s %-16s %-4s" % ("PID", "COMM", "SADDR", "DADDR", "COUNT"))

def inet_ntoa(addr):
    return ".".join(str(addr >> i & 0xFF) for i in (0, 8, 16, 24))

# Filter and format output
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
    if _tag.decode() != "trace_nf_hook_slow":
        continue

    # Print the tracing information
    printb(b"%-6d %-12.12s %-16s %-16s %-4s" % (pid, task, 
        inet_ntoa(int(saddr_hs, 16)).encode(),
        inet_ntoa(int(daddr_hs, 16)).encode(), count))