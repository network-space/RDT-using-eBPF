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
u char ptc0,ptc1;	//algoritma için gerekli. Son paketler alındığında kümülatif olarak hedeflediğimizden az sayıda ack varsa onları yolluyoruz. Yalnız bunu uygulamamışıoz Şu an düzgün çalışmıyor.

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2);
} rbrk SEC(".maps");

u char pl;	//payload (not sure if it is used)

//for debug
u char da[65];
u char ptt;
u char aca0;
u char aca2[10];	//ack array debug

#define ptac(pti) if ((void*)c->d + pti+1 > (void*)c->de)	goto e
///label e(nd)

u char fs,pds,acc;

//dynamic allocation is not allowed
u char payload0;
u char aca[222+255];	//ack array
//used for cumulative ack
//aca[0] is the number of acks inside array. The rest are packet indices

SEC("s")
int pm(struct xdp_md *c)
{
	t = bpfktgtains();

	ptac(9);
	if (((u char *)(c->d))[9] != 0xe8)	goto e;	//sender's MACA.3
	ptac(62);
	switch (((u char *)(c->d))[62])	//packet type
	{
		case 0:	//metadatapacket
			ptc0++;
			ptac(65);
			fs = ((u char *)(c->d))[63], pds = ((u char *)(c->d))[64], acc = ((u char *)(c->d))[65];

			for (u char i=0,s; i<6; i++)	//swap MAC a.
			{
				ptac(i);
				s = ((u char *)(c->d))[i];
				ptac(i+6);
				((u char *)(c->d))[i] = ((u char *)(c->d))[i+6];
				ptac(i+6);
				((u char *)(c->d))[i+6] = s;
			}
			for (u char i=61,s; i>(61-16); i--)	//swap ipv6 a.
			{
				ptac(i);
				s = ((u char *)(c->d))[i];
				ptac(i-16);
				((u char *)(c->d))[i] = ((u char *)(c->d))[i-16];
				ptac(i-16);
				((u char *)(c->d))[i-16] = s;
			}
			u char md[4] = {0,fs,pds,acc};
			bpf_ringbuf_output(&rbrk, md, sizeof(md), 0);	//send metadata to userspace
			return XDP_TX;
		case 1:	//data
			ptc1++;
			static u char pl[2+255];
			u char pts = pds+2;	//packet size
			for (u char pti=0; pti<pts; pti++)
			{
				ptac(62+pti);
				pl[pti] = ((u char *)(c->d))[62+pti];
			}
			bpf_ringbuf_output(&rbrk, pl, pts, 0);	//send payload to userspace

			for (u char i=0,s; i<6; i++)	//swap MAC a.
			{
				ptac(i);
				s = ((u char *)(c->d))[i];
				ptac(i+6);
				((u char *)(c->d))[i] = ((u char *)(c->d))[i+6];
				ptac(i+6);
				((u char *)(c->d))[i+6] = s;
			}
			for (u char i=61,s; i>(61-16); i--)	//swap ipv6 a.
			{
				ptac(i);
				s = ((u char *)(c->d))[i];
				ptac(i-16);
				((u char *)(c->d))[i] = ((u char *)(c->d))[i-16];
				ptac(i-16);
				((u char *)(c->d))[i-16] = s;
			}
			if (1+aca[0] >= sizeof(aca))	//redundant but for verification
				goto e;
			ptac(63);	//redundant but for verification
			aca[1+aca[0]] = ((u char *)(c->d))[63];
			aca[0]++;
			if (aca[0] >= acc)	//sending cumulative ack with dynamic size using TX
			{
				ptac(62);
				((u char *)(c->d))[62] = 2;	//ack
				u char _acc = acc+1;	//if you do not do this verifier will complain about some horribly long recursive kuruntu
				for (u char acci=0; acci < _acc; acci++)
				{
					if ((void*)c->d + 63+acci +1 > (void*)c->de)
					{
						bpf_xdp_adjust_tail(c,1);
						ptac(63+acci);
					}
					ptac(63+acci);
					if (sizeof(aca) <= acci)	goto e;
					((u char *)(c->d))[63+acci] = aca[acci];
				}
				for (u char pti=0; pti<65; pti++)
				{
					ptac(pti);
					da[pti] = ((u char *)(c->d))[pti];
				}
				for (u char pti=0; pti<10; pti++)
				{
					aca2[pti] = aca[pti];
				}
				aca[0]=0;	//reset ack count
				t1 = bpfktgtains();
				t0=t;
				return XDP_TX;
			}
			return XDP_DROP;
	}
	e:	return XDP_PASS;
}
/*
clang -target bpf -c RK.c -o RK.o -g -O1
ixdpt="ens3 xdpgeneric"
sudo ip link set dev $ixdpt off
sudo ip link set dev $ixdpt obj RK.o sec s

sudo bpftool map dump name RK.bss
*/
char _license[] SEC("license") = "GPL";