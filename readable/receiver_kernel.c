/* SPDX-License-Identifier: GPL-2.0 */
// Receiver Kernelspace
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

unsigned long int t, t0, t1;
unsigned char ptc, ptc2; // algoritma için gerekli. Son paketler alındığında kümülatif olarak hedeflediğimizden az sayıda ack varsa onları yolluyoruz. Yalnız bunu uygulamamışıoz Şu an düzgün çalışmıyor.

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} rbrk SEC(".maps");

unsigned char pl; // payload (not sure if it is used)

// for debug
unsigned char da[14];
unsigned char ptt;

#define PACKET_ACCESS_CHECK(packet_index)                                   \
	if ((void *)context->data + packet_index + 1 > (void *)context->data_end) \
	goto e // packet access check

unsigned char fs, pds, acc;

// dynamic allocation is not allowed
unsigned char d[2 + 255], payload0;
unsigned char aca[1 + 255]; // ack array
// used for cumulative ack
// aca[0] is the number of acks inside array. The rest are packet indices

SEC("receiver_start")
int pm(struct xdp_md *context)
{
	t = bpf_ktime_get_tai_ns();

	PACKET_ACCESS_CHECK(9);
	if (((unsigned char *)(context->data))[9] != 0xe8)
		goto e; // sender's MACA.3
	ptc2++;
	PACKET_ACCESS_CHECK(62);
	switch (((unsigned char *)(context->data))[62]) // packet type
	{
	case 0: // metadatapacket
		ptc++;
		PACKET_ACCESS_CHECK(65);
		fs = ((unsigned char *)(context->data))[63], pds = ((unsigned char *)(context->data))[64], acc = ((unsigned char *)(context->data))[65];

		for (unsigned char i = 0, s; i < 6; i++) // swap MAC a.
		{
			PACKET_ACCESS_CHECK(i);
			s = ((unsigned char *)(context->data))[i];
			PACKET_ACCESS_CHECK(i + 6);
			((unsigned char *)(context->data))[i] = ((unsigned char *)(context->data))[i + 6];
			PACKET_ACCESS_CHECK(i + 6);
			((unsigned char *)(context->data))[i + 6] = s;
		}
		for (unsigned char i = 61, s; i > (61 - 16); i--) // swap ipv6 a.
		{
			PACKET_ACCESS_CHECK(i);
			s = ((unsigned char *)(context->data))[i];
			PACKET_ACCESS_CHECK(i - 16);
			((unsigned char *)(context->data))[i] = ((unsigned char *)(context->data))[i - 16];
			PACKET_ACCESS_CHECK(i - 16);
			((unsigned char *)(context->data))[i - 16] = s;
		}
		return XDP_TX;
	}
	PACKET_ACCESS_CHECK(62);
	payload0 = ((unsigned char *)(context->data))[62];
	for (unsigned char di = 0; di < 66; di++)
	{
		PACKET_ACCESS_CHECK(di);
		pl = d[di] = ((unsigned char *)(context->data))[di]; // copy data into pointer
	}

	bpf_ringbuf_output(&rbrk, d, sizeof(d), 0); // send packet to userspace

	goto e;

	if (1 + aca[0] >= sizeof(aca)) // redundant but for verification
		goto e;
	PACKET_ACCESS_CHECK(0); // redundant but for verification
	aca[1 + aca[0]] = ((unsigned char *)(context->data))[0];
	ptc++, aca[0]++;
	if (aca[0] >= acc) // sending cumulative ack with dynamic size using TX
	{
		if (context->data_end - context->data > 14)
			bpf_xdp_adjust_tail(context, 1 + sizeof(aca) - (context->data_end - context->data));
		PACKET_ACCESS_CHECK(0);
		((unsigned char *)(context->data))[0] = 0;
		for (unsigned char pti = 0; pti < sizeof(aca); pti++)
		{
			PACKET_ACCESS_CHECK(1 + pti); // redundant but for verification	sürekli check etmemek de çalışıyorsa optimize edilveilir.
			((unsigned char *)(context->data))[1 + pti] = aca[pti];
		}
		aca[0] = 0; // reset ack count
		t1 = bpf_ktime_get_tai_ns();
		t0 = t;
		return XDP_TX;
	}
	t1 = bpf_ktime_get_tai_ns();
	t0 = t;
	return XDP_DROP; // do not send ack
e:
	return XDP_PASS;
}
/*
ixdpt="ens3 xdpgeneric"
sudo ip link set dev $ixdpt off
clang -target bpf -c receiver_kernel.c -o receiver_kernel.o -g -O1
sudo ip link set dev $ixdpt obj receiver_kernel.o sec receiver_start

sudo bpftool map dump name receiver_kernel.bss
*/
char _license[] SEC("license") = "GPL";