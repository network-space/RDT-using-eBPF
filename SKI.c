/* SPDX-License-Identifier: GPL-2.0 */
// Sender Kernelspace Input

// Not sure about all the headers here are used or not. Shall be reduced
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

// common definitions. Check before continueing
// #include "k.h"
#include "c.h"

// obvious
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} rbsik SEC(".maps");

// Nanosaniye cinsinden an ölçümü ve debugging için global variabls
u l int t, t0, t1;
u char ptc0,ptc2,ptc3; // packet counts by type
u char d[2 + 255];
u char fs, pds, acc;
unsigned char anan[1000];
unsigned char anasayar;

#define ptac(pti)                             \
	if ((void *)c->d + pti + 1 > (void *)c->de) \
	goto e // packet access check

SEC("s")								 // programı kernele yüklerken lazım olcak, adın aynı olması dışında bi numarası yok
int pm(struct xdp_md *c) // p(rogra)m.	c(ontext)
{
	t = bpfktgtains();
	
	ptac(9);
	if (((u char *)(c->d))[9] != 0x19)
		goto e;


	/// use ptac() instea of nested stupid if blocks

	//...
	/* anasayar++;
	if (anasayar > 80) goto e;
	for (int i = 0; i < 10; i++){
		ptac(62+i);
		anan[i+anasayar*10] = ((u char *)(c->d))[62+i];
	} */
	ptac(62);
	switch (((u char *)(c->d))[62])
	{
	case 0:
		ptc0++;
		ptac(65);
		fs = ((u char *)(c->d))[63], pds = ((u char *)(c->d))[64], acc = ((u char *)(c->d))[65];
		ptac(0);
		if (((u char *)(c->d))[0])	for (u char di = 0; di < 66; di++)
		{
			ptac(di);
			d[di] = ((u char *)(c->d))[di]; // copy data into pointer
		}
		{//output to ring buffer to send userspace that the metadata is acknowledged
			u char rbo=0;
			bpf_ringbuf_output(&rbsik, &rbo, 1, 0);
		}
		return XDP_DROP;
	case 2: // ack
		ptc2++;
		ptac(63);	
		u char acco = ((u char *)(c->d))[63];
		for (u char aci = 0; aci < acco; aci++)
		{
			u char rbo[2] = {2};
			ptac(64 + aci);
			rbo[1] = ((u char *)(c->d))[64 + aci];
			bpf_ringbuf_output(&rbsik, rbo, 2, 0);
		}
		break;
	case 3: // nack
		ptc3++;
		goto e;
		u char rbo[2] = {3, 0};
		ptac(63);
		u char pti = ((u char *)(c->d))[63];
		rbo[1] = pti;
		bpf_ringbuf_output(&rbsik, rbo, 2, 0);
	}
	goto e;

	/// indent using tabs please.

	t1 = bpfktgtains();
	t0 = t; // debugging actions had better not be included while we measure time
	return XDP_DROP;
e:
	return XDP_PASS;
}
/*
ixdpt="ens3 xdpgeneric"
sudo ip link set dev $ixdpt off
clang -target bpf -c SKI.c -o SKI.o -g -O1
sudo ip link set dev $ixdpt obj SKI.o sec s

sudo bpftool map dump name SKI.bss
//to view global variables for measurement

//compilation variables:
	i(nterface):	ens3
	xdp t(ype):	xdpgeneric kullandım ki xdp ile karşılaştırabilelim.
	O1 lazım en az
*/
char _license[] SEC("license") = "GPL";