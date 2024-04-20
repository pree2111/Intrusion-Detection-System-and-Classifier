#handling of ipv4 as well as ipv6 addresses
#Script is modified from the sciptes provide by Brendan Gregg as a par of the bcc library
#probes attatched to the wrong functions. these probes activate when connections tcp are established
#In your program, `kprobe__tcp_v4_connect` and `kretprobe__tcp_v4_connect` are not packet-in and packet-out functions. They are kernel probes that are triggered when the `tcp_v4_connect` function is called and returns in the kernel, respectively. The `tcp_v4_connect` function is part of the TCP stack in the Linux kernel and is called when a TCP connection is being established, not for each packet sent or received.
#For incoming packets, we might want to attach a kprobe to the `tcp_v4_do_rcv` function, which is called when a TCP packet is received. For outgoing packets, you might want to attach a kprobe to the `tcp_transmit_skb` function, which is called when a TCP packet is sent.
#problem with source and destination addresses- like source is always same while destination is diifferent. should be opposite
#okay so source is actually my address? wlp0s20f3 is my interface. but why? isn't this about incoming packets? have to check
# it says that to check what the matter is and why this is happening we should print out the source and destination ports.
##If the source port is a high-numbered ephemeral port and the destination port is a well-known port (e.g., 80 for HTTP or 443 for HTTPS), then the packets are likely outgoing packets from your machine. If the source port is a well-known port and the destination port is a high-numbered ephemeral port, then the packets are likely incoming packets to your machine.
# bit messed up. i am pretty confused right now. like sport and port are super random, probably because it is capturing all recieving packets instead of just connected tcp connections.
#i think dport and sport meaning are lining up with the rcv function but ofc i cant see any popoular ports in the listing. bit weird.
# i think sport and sport are being shown correctly
# chatgpt says that sourceip will be mostly the ip of the machine on which the bpf program is running
#im gonna try to modify this according to the suggestion given by chatgpt which is in the program changed_stack.py where i attatch the probe to a different function in the tcp stack
#still still still getting the same thing. this is annoying. gonna leave it now and just focus on other stuff. tysm.


from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);
BPF_HASH(packet_cnt, u64, long, 256);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	currsock.update(&pid, &sk);

	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{	
	long initial_count = 0;
	long *count = &initial_count;
    long one = 1;
	u64 pass_value = 0;
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		currsock.delete(&pid);
		return 0;
	}

	// pull in details
	struct sock *skp = *skpp;
	u32 saddr = skp->__sk_common.skc_rcv_saddr;
	u32 daddr = skp->__sk_common.skc_daddr;
	u16 dport = skp->__sk_common.skc_dport;

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
	currsock.delete(&pid);

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
