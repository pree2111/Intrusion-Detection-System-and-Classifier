from bcc import BPF

# BPF program code
bpf_code = """
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

BPF_HASH(packet_count);

int packet_counter(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb);
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

    // Filter packets based on protocol (e.g., TCP)
    if (eth->h_proto != htons(ETH_P_IP) || ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // Increment packet count
    u64 *count = packet_count.lookup(&tcp->daddr);
    if (count) {
        (*count)++;
    } else {
        u64 new_count = 1;
        packet_count.update(&tcp->daddr, &new_count);
    }

    return XDP_PASS;
}
"""

# Load and attach the BPF program
b = BPF(text=bpf_code)
fn = b.load_func("packet_counter", BPF.XDP)

# Attach the BPF program to a network interface
interface = "eth0"  # Replace with your desired interface
b.attach_xdp(interface, fn)

# Retrieve and print the packet counts
packet_count = b.get_table("packet_count")
for k, v in packet_count.items():
    print(f"Destination IP: {k.value}, Packet Count: {v.value}")

# Detach the BPF program from the network interface
b.remove_xdp(interface)