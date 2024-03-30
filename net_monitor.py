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
    
	bpf_trace_printk("trace_tcp4connect %x %x %ld\\n", saddr, daddr, count);

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
