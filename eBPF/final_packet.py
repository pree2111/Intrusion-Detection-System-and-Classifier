from bcc import BPF
import ctypes as ct
import time
import csv

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/ip.h>
#include <bcc/proto.h>

struct info {
    u64 incoming_pkt_count;
    u64 outgoing_pkt_count;
    u8 protocol;
    u32 saddr;
    u32 daddr;
    u64 timestamp;
    u64 bytes;
};

BPF_HASH(packet_info, u64, struct info, 256);

int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
    struct info pkt_info = {};
    u64 pass_value = 0;

    struct iphdr *ip_header = (struct iphdr *)(skb->data);

    pkt_info.saddr = ip_header->saddr;
    pkt_info.daddr = ip_header->daddr;
    pkt_info.protocol = ip_header->protocol;
    pkt_info.timestamp = bpf_ktime_get_ns();
    pkt_info.bytes = skb->len; // Get packet size

    pass_value = pkt_info.saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + pkt_info.daddr;

    struct info *info = packet_info.lookup_or_init(&pass_value, &pkt_info);
    info->incoming_pkt_count++;

    bpf_trace_printk("IN %x %x\\n", pkt_info.saddr, pkt_info.daddr);

    return 0;
}

int kprobe__ip_finish_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct info pkt_info = {};
    u64 pass_value = 0;

    struct iphdr *ip_header = (struct iphdr *)(skb->data);

    pkt_info.saddr = ip_header->saddr;
    pkt_info.daddr = ip_header->daddr;
    pkt_info.protocol = ip_header->protocol;
    pkt_info.timestamp = bpf_ktime_get_ns();
    pkt_info.bytes = skb->len; // Get packet size

    pass_value = pkt_info.daddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + pkt_info.saddr;

    struct info *info = packet_info.lookup_or_init(&pass_value, &pkt_info);
    info->outgoing_pkt_count++;

    bpf_trace_printk("OUT %x %x\\n", pkt_info.daddr, pkt_info.saddr);

    return 0;
}
"""

# Define protocol names
protocol_names = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    # Add more protocol numbers and their corresponding names as needed
}

# Initialize BPF
b = BPF(text=bpf_text)

# Header for CSV file
header = ["TYPE", "SADDR", "DADDR", "PROTOCOL", "I-COUNT", "O-COUNT", "TIMESTAMP", "BYTES"]

def inet_ntoa(addr):
    return ".".join(str(addr >> i & 0xFF) for i in (0, 8, 16, 24))

# Open CSV file for writing
with open('packet_info.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(header)

    # Filter and format output
    while True:
        # Read messages from the kernel pipe
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            (_type, saddr_hs, daddr_hs) = msg.split(b" ")
        except ValueError:
            # Ignore messages from other tracers
            continue
        except KeyboardInterrupt:
            exit()

        # Convert hexadecimal addresses to IP format
        saddr = inet_ntoa(int(saddr_hs, 16))
        daddr = inet_ntoa(int(daddr_hs, 16))

        # Convert pass_value to ctypes object
        pass_value = int(saddr_hs, 16) << 32 | int(daddr_hs, 16)
        pass_value_ctypes = ct.c_ulonglong(pass_value)

        # Get struct info from map
        info = b["packet_info"].get(pass_value_ctypes)
        if not info:
            # If no info found, continue to the next iteration
            continue

        # Convert protocol number to name
        protocol_name = protocol_names.get(info.protocol, "UNKNOWN")

        # Convert timestamp to human-readable format
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info.timestamp / 1e9))

        # Write row to CSV file
        row = [_type.decode(), saddr, daddr, protocol_name, info.incoming_pkt_count, info.outgoing_pkt_count, timestamp, info.bytes]
        writer.writerow(row)
