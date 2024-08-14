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

#include "c.h"
//#include "k.h"

u l int t, t0,t1;
u char ptc;	//algoritma için gerekli. Son paketler alındığında kümülatif olarak hedeflediğimizden az sayıda ack varsa onları yolluyoruz. Yalnız bunu uygulamamışıoz Şu an düzgün çalışmıyor.

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} rbrk SEC(".maps");

u char pl;	//payload (not sure if it is used)

//for debug
u char da[14];
u char ptt;

#define ptac(pti) if ((void*)c->d + pti+1 > (void*)c->de)	goto e
///label e(nd)

u char fs,pds,acc;

//dynamic allocation is not allowed
u char d[2+255];
u char aca[1+255];	//ack array
//used for cumulative ack
//aca[0] is the number of acks inside array. The rest are packet indices

SEC("xdp")
int pm(struct xdp_md *c)
{
	t = bpfktgtains();

	ptac(9);
	if (((u char *)(c->d))[9] != 0xe8)	goto e;	//sender's MACA.3

	ptac(62);
	if (((u char *)(c->d))[62] == 0)	//metadatapacket
	{
		ptc++;
		ptac(65);
		fs = ((u char *)(c->d))[63], pds = ((u char *)(c->d))[64], acc = ((u char *)(c->d))[65];
		return XDP_TX;
	}
	for (u char di=0; di < 66; di++)
	{
		ptac(di);
		pl = d[di] = ((u char *)(c->d))[di];	//copy data into pointer
	}

	bpf_ringbuf_output(&rbrk, d, sizeof(d), 0);	//send packet to userspace

	goto e;


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
ixdpt="ens3 xdpgeneric"
sudo ip link set dev $ixdpt off
gcc -march=bpf -c RK.c -o RK.o -g -O1
sudo ip link set dev $ixdpt obj RK.o sec xdp

sudo bpftool map dump name RK.bss
*/
char _license[] SEC("license") = "GPL";