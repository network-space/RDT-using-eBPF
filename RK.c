/* SPDX-License-Identifier: GPL-2.0 */
//Receiver Kernelspace

#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "k.h"
#include "c.h"

u l int t, t0,t1;
u char ptc;	//algoritma için gerekli. Son paketler alındığında kümülatif olarak hedeflediğimizden az sayıda ack varsa onları yolluyoruz. Yalnız bunu uygulamamışıoz Şu an düzgün çalışmıyor.

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} rbrk SEC(".maps");

u char aca[1+acc];	//ack array
//used for cumulative ack
//aca[0] eventually is the number of acks inside array. The rest are packet indices

u char pl;	//payload (not sure it is used)

#define ptac(pti) if ((void*)c->d + pti+1 > (void*)c->de)	goto e

SEC("xdp")
int pm(struct xdp_md *c)
{
	t = bpfktgtains();

	ptac(pds);

	/// ((u char *)(c->d)) is the packet pointer

	u char d[pds+1];
	for (u char di=0; di<pds+1; di++)	pl = d[di] = ((u char *)(c->d))[di];	//copy data into pointer
	bpf_ringbuf_output(&rbrk, d, sizeof(d), 0);	//send packet to userspace

	///label e(nd)

	if (1+aca[0] >= sizeof(aca))	//redundant but for verification
		goto e;
	ptac(0);	//redundant but for verification
	aca[1+aca[0]] = ((u char *)(c->d))[0];
	ptc++, aca[0]++;
	if (aca[0] >= acc)	//sending cumulative ack with dynamic size using TX
	{
		if (c->de - c->d > 14)	bpf_xdp_adjust_tail(c, 1 + sizeof(aca) - (c->de - c->d));
		ptac(0);
		((u char *)(c->d))[0] = 0;
		for (u char pti=0; pti < sizeof(aca); pti++)
		{
			ptac(1+pti);	//redundant but for verification	sürekli check etmemek de çalışıyorsa optimize edilveilir.
			((u char *)(c->d))[1+pti] = aca[pti];
		}
		aca[0]=0;	//reset ack count
		t1 = bpfktgtains();
		t0=t;
		return XDP_TX;
	}
	t1 = bpfktgtains();
	t0=t;
	return XDP_DROP;	//do not send ack 
	e:	return XDP_PASS;
}
/*
sudo ip netns exec n2 ip link set dev ven2 xdp off
clang -c RK.c -o RK.o -target bpf -g -O1 -fno-builtin
e n2 ip link set dev ven2 xdp obj RK.o sec xdp

sudo bpftool map dump name RK.bss
*/
char _license[] SEC("license") = "GPL";