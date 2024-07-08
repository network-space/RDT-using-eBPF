/* SPDX-License-Identifier: GPL-2.0 */
//Sender Kernelspace Input

//Not sure about all the headers here are used or not. Shall be reduced
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

//common definitions. Check before continueing
#include "k.h"
#include "c.h"

//obvious
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} rbsik SEC(".maps");

//Nanosaniye cinsinden an ölçümü ve debugging için global variabls
u l int t, t0,t1;
u char ptc;	//packet count

#define ptac(pti) if ((void*)c->d + pti+1 > (void*)c->de)	goto e	//packet access check

SEC("xdp")
int pm(struct xdp_md *c)	//p(rogra)m.	c(ontext)
{
	t = bpfktgtains();

	ptac(acc+2);	//instea of nested stupid if blocks

	u char ptt = ((u char *)(c->d))[0];	//p(acke)t t(ype)
	switch(ptt)
	{
		case 0:	//ack
			u char acco = ((u char *)(c->d))[1];
			for (u char aci=0; aci < acco; aci++)
			{
				u char rbo[2] = {0,0};
				ptac(2+aci);
				rbo[1] = ((u char *)(c->d))[2+aci];
				bpf_ringbuf_output(&rbsik, rbo, 2, 0);
			}
			break;
		case 1:	//nack
			u char rbo[2] = {1,0};
			ptac(1);
			u char pti = ((u char *)(c->d))[1];
			rbo[1]=pti;
			bpf_ringbuf_output(&rbsik, rbo, 2, 0);
	}
	
	///indent using tabs please.

	t1 = bpfktgtains();
	ptc++;
	t0=t;	//debugging actions had better not be included while we measure time
	return XDP_DROP;
	e:	return XDP_PASS;
}
/*
sudo ip netns exec n1 ip link set dev ven1 xdp off
clang -c SKI.c -o SKI.o -target bpf -g -O1 -fno-builtin
sudo ip netns exec n1 ip link set dev ven1 xdp obj SKI.o sec xdp

//compilation variables:
	xdpgeneric kullandım ki xdp ile karşılaştırabilelim.
	-O1	minimum optimization needed
	-fno-builtin	Bunu etkisi var mı bilmiyorum. Built*in fonlsitonları optimize etme diyorsun.

//to view global variables for measurement:
sudo bpftool map dump name SKI.bss
*/
char _license[] SEC("license") = "GPL";