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

SEC("s")	//programı kernele yüklerken lazım olcak, adın aynı olması dışında bi numarası yok
int pm(struct xdp_md *c)	//p(rogra)m.	c(ontext)
{
	t = bpfktgtains();
	
	ptac(9);
	if (((u char *)(c->d))[9] != 0x19)	goto e;

	/// use ptac() instea of nested stupid if blocks

	//...
	ptac(0);
	switch (((u char *)(c->d))[0])
	{
		case 2:	//ack
			ptac(1);	u char acco = ((u char *)(c->d))[1];
			for (u char aci=0; aci < acco; aci++)
			{
				u char rbo[2] = {2};
				ptac(2+aci);
				rbo[1] = ((u char *)(c->d))[2+aci];
				bpf_ringbuf_output(&rbsik, rbo, 2, 0);
			}
			break;
		case 3:	//nack
			u char rbo[2] = {3,0};
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
ixdpt="ens3 xdpgeneric"
sudo ip link set dev $ixdpt off
gcc -march=bpf -c SKI.c -o SKI.o -gbtf -O1
sudo ip link set dev $ixdpt obj SKI.o sec s

sudo bpftool map dump name SKI.bss
//to view global variables for measurement

//compilation variables:
	i(nterface):	ens3
	xdp t(ype):	xdpgeneric kullandım ki xdp ile karşılaştırabilelim.
	O1 lazım en az
*/
char _license[] SEC("license") = "GPL";