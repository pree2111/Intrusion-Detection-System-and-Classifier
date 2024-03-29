#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import strftime

# Import required modules

# Define the eBPF program
ebpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>

struct key_t {
    u32 saddr;
    u32 daddr;
};

BPF_HASH(packet_count, struct key_t);
BPF_HASH(timestamps, struct key_t, u64);

int packet_counting(struct __sk_buff *skb) {
    u32 saddr = skb->saddr;
    u32 daddr = skb->daddr;

    struct key_t key = {};
    key.saddr = saddr;
    key.daddr = daddr;

    u64 *count = packet_count.lookup(&key);
    if (count) {
        (*count)++;
    } else {
        packet_count.update(&key, &(u64){1});
    }

    u64 *timestamp = timestamps.lookup(&key);
    if (timestamp) {
        *timestamp = bpf_ktime_get_ns();
    } else {
        timestamps.update(&key, &(u64){bpf_ktime_get_ns()});
    }

    return 0;
}
"""

# Create the BPF object and load the eBPF program
b = BPF(text=ebpf_program)
fn = b.load_func("packet_counting", BPF.SCHED_CLS)

# Attach the eBPF program to the network interface
BPF.attach_raw_socket(fn, "eth0")

# Print the packet count and timestamps
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        key = b["packet_count"].get_key(task)
        count = b["packet_count"][key].value
        timestamp = b["timestamps"][key].value
        print("Source: {}, Destination: {}, Count: {}, Timestamp: {}".format(
            key.saddr, key.daddr, count, strftime("%Y-%m-%d %H:%M:%S", localtime(timestamp / 1000000000))))
    except KeyboardInterrupt:
        exit()
        # Record destination to source packet count
        key.daddr = saddr
        key.saddr = daddr

        # Record source to destination packet count
        key.saddr = saddr
        key.daddr = daddr