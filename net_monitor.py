#!/usr/bin/python
#
# tcpv4connect    Trace TCP IPv4 connect()s and count packets.
#        For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4connect [-h] [-t] [-p PID]
#
# This script traces TCP IPv4 connect()s and counts packets.
#
# All IPv4 connection attempts are traced, even if they ultimately fail.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Oct-2015    Brendan Gregg    Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb


import ctypes as ct

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);
BPF_HASH(packet_count, struct key_t, u64);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();

    // Stash the sock ptr for lookup on return
    currsock.update(&pid, &sk);

    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;    // Missed entry
    }

    if (ret != 0) {
        // Failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&pid);
        return 0;
    }

    // Pull in details
    struct sock *skp = *skpp;
    u32 saddr = skp->__sk_common.skc_rcv_saddr;
    u32 daddr = skp->__sk_common.skc_daddr;
    u16 dport = skp->__sk_common.skc_dport;

    // Create key for packet count hash map
    struct key_t key = {.saddr = saddr, .daddr = daddr};

    // Count packet
    u64 *count = packet_count.lookup(&key);
    if (count) {
        (*count)++;
    } else {
        packet_count.update(&key, &(u64){1});
    }

    // Output connection details
    bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, ntohs(dport));

    currsock.delete(&pid);

    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)

# Header
print("%-6s %-12s %-16s %-16s %-4s %-8s" % ("PID", "COMM", "SADDR", "DADDR",
    "DPORT", "PACKET COUNT"))

def inet_ntoa(addr):
    dq = b''
    for i in range(0, 4):
        dq = dq + str(addr & 0xff).encode()
        if (i != 3):
            dq = dq + b'.'
        addr = addr >> 8
    return dq

# Filter and format output
while 1:
    # Read messages from kernel pipe
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (_tag, saddr_hs, daddr_hs, dport_s) = msg.split(b" ")
    except ValueError:
        # Ignore messages from other tracers
        continue
    except KeyboardInterrupt:
        exit()

    # Ignore messages from other tracers
    if _tag.decode() != "trace_tcp4connect":
        continue

    # Retrieve packet count
    saddr = int(saddr_hs, 16)
    daddr = int(daddr_hs, 16)
    dport = int(dport_s)
    key = b["packet_count"].get_key(saddr)
    count = b["packet_count"][key].value if key else 0

    # Print connection details and packet count
    printb(b"%-6d %-12.12s %-16s %-16s %-4d %-8d" % (pid, task,
        inet_ntoa(saddr), inet_ntoa(daddr), dport, count))
