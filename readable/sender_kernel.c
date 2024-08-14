/* SPDX-License-Identifier: GPL-2.0 */
// Sender Kernelspace Input
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// obvious
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} rbsik SEC(".maps");

// Nanosaniye cinsinden an ölçümü ve debugging için global variabls
unsigned long int t, t0, t1;
unsigned char packet_count; // packet count
unsigned char data_array[2 + 255];
unsigned char file_size, packet_data_size, ack_cumulativity;

#define PACKET_ACCESS_CHECK(packet_index)                                   \
	if ((void *)context->data + packet_index + 1 > (void *)context->data_end) \
	goto e // packet access check

SEC("sender_start") // programı kernele yüklerken lazım olcak, adın aynı olması dışında bi numarası yok
int program(struct xdp_md *context)
{
	t = bpf_ktime_get_tai_ns();

	PACKET_ACCESS_CHECK(9);
	if (((unsigned char *)(context->data))[9] != 0x19)
		goto e;

	/// use PACKET_ACCESS_CHECK() instea of nested stupid if blocks

	//...
	/* anasayar++;
	if (anasayar > 80) goto e;
	for (int i = 0; i < 10; i++){
		PACKET_ACCESS_CHECK(62+i);
		anan[i+anasayar*10] = ((unsigned char *)(context->data))[62+i];
	} */
	PACKET_ACCESS_CHECK(62);
	switch (((unsigned char *)(context->data))[62])
	{
	case 0:
		packet_count++;
		PACKET_ACCESS_CHECK(65);
		file_size = ((unsigned char *)(context->data))[63], packet_data_size = ((unsigned char *)(context->data))[64], ack_cumulativity = ((unsigned char *)(context->data))[65];
		PACKET_ACCESS_CHECK(0);
		if (((unsigned char *)(context->data))[0])
			for (unsigned char di = 0; di < 66; di++)
			{
				PACKET_ACCESS_CHECK(di);
				data_array[di] = ((unsigned char *)(context->data))[di]; // copy data into pointer
			}
		{ // output to ring buffer to send userspace that the metadata is acknowledged
			unsigned char rbo = 0;
			bpf_ringbuf_output(&rbsik, &rbo, 1, 0);
		}
		return XDP_DROP;
	case 2: // ack
		PACKET_ACCESS_CHECK(63);
		unsigned char acco = ((unsigned char *)(context->data))[63];
		for (unsigned char aci = 0; aci < acco; aci++)
		{
			unsigned char rbo[2] = {2};
			PACKET_ACCESS_CHECK(64 + aci);
			rbo[1] = ((unsigned char *)(context->data))[64 + aci];
			bpf_ringbuf_output(&rbsik, rbo, 2, 0);
		}
		break;
	case 3: // nack
		unsigned char rbo[2] = {3, 0};
		PACKET_ACCESS_CHECK(63);
		unsigned char packet_index = ((unsigned char *)(context->data))[63];
		rbo[1] = packet_index;
		bpf_ringbuf_output(&rbsik, rbo, 2, 0);
	}

	/// indent using tabs please.

	t1 = bpf_ktime_get_tai_ns();
	packet_count++;
	t0 = t; // debugging actions had better not be included while we measure time
	return XDP_DROP;
e:
	return XDP_PASS;
}
/*
ixdpt="ens3 xdpgeneric"
sudo ip link set dev $ixdpt off
clang -target bpf -c sender_kernel.c -o sender_kernel.o -g -O1
sudo ip link set dev $ixdpt obj sender_kernel.o sec sender_start

sudo bpftool map dump name sender_kernel.bss
//to view global variables for measurement

//compilation variables:
	i(nterface):	ens3
	xdp t(ype):	xdpgeneric kullandım ki xdp ile karşılaştırabilelim.
	O1 lazım en az
*/
char _license[] SEC("license") = "GPL";