//Sender Userspace
#include "us.h"

//userspace eBPF program includes
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

//network send/receive...
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#include <time.h>
#define tai(var) clock_gettime(CLOCK_TAI, &var)	//TAI clcok get time
#define ts timespec

#include "c.h"

#define ra (rand()%256)	//random byte
#define p printf
#define so sizeof
#define a14(na, si) na[(si<14) ? 14 : (si)]	//create a array whose size is max(14, si) with na(me)

//g(et) f(ile) d(escriptor) of ring buffer
static int gfd(char *name, int **fds)
{
	unsigned int id = 0;
	int fd, nb_fds = 0;
	void *tmp;
	int err;

	while (true) {
		struct bpf_map_info info = {};
		__u32 len = sizeof(info);

		err = bpf_map_get_next_id(id, &id);
		if (err) {
			return nb_fds;
		}

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0) {
			goto err_close_fds;
		}

		err = bpf_map_get_info_by_fd(fd, &info, &len);
		if (err) {
			goto err_close_fd;
		}

		if (strncmp(name, info.name, BPF_OBJ_NAME_LEN)) {
			close(fd);
			continue;
		}

		if (nb_fds > 0) {
			tmp = realloc(*fds, (nb_fds + 1) * sizeof(int));
			if (!tmp) {
				goto err_close_fd;
			}
			*fds = tmp;
		}
		(*fds)[nb_fds++] = fd;
	}

	err_close_fd:
		close(fd);
	err_close_fds:
		while (--nb_fds >= 0)
			close((*fds)[nb_fds]);
		return -1;
}

u char *fa;	//file ack array. Will hold whether or not each packet's ack has come
int rbcfn(void*c, void*d, size_t s)	//r(ing) b(uffer) c(onsuming) f(unctio)n
//c(ontext): ne olduğunu bimiyom kullanmıyıoz
//d(ata) is array of s(ize) bytes
{	//ring buffer'a veri geldiği poll fonksiyonunca anlaşıldıkça bu fonksiyon çağrılıyuor. Ya da ringbuffernew gibi bir fn. ile ring buffer oluşturukuynca? Wmin değilim.
	if (s==1)
	{
		p("size low");
	}	
	switch (((u char *)d)[0])
	{
		case 0:
			if (((u char *)d)[1] == 2)	p("ack%hhu\n", ((u char *)d)[1] );
			fa[((u char *)d)[1]]=1;
		break;	//ack
		case 1:	fa[((u char *)d)[1]]=0;	p("nack%hhu, %hhu\n", ((u char *)d)[1], ((u char *)d)[0]);	//nack
	}
	return 0;
}

int main(int arc, char** ars)	//argumenty callable
//arc: ar(gument) c(ount)
//ars: ar(gument)s
{	//call it like below.
//SU fs pds acc
//so for example SU 32 4 2 means Each file consists of 32 bytes, to be sent 4 bytes per packet, a single ack can include at most 4 packets' ack
	p("\n");

	char fs,pds,pcif,re,acc;
	//fs : f(ile) s(ize)
	//p(acket) d(ata) s(ize)
	//p(acket) c(ount) i(n) f(iles)
	//re(petition of experiment) (number of files to be sent)
	//ac(knowledgement) c(umulativity)
	if (arc>=4)	fs = atoi(ars[1]), pds = atoi(ars[2]), acc = atoi(ars[3]);
	pcif = fs/pds, re=1;
	u char _fa[pcif];	fa=_fa;	//since fa must be global...

	srand(time(0));	//initialize randomizeerr

	struct ring_buffer *rb;
	int fd=0, *fdp=&fd;
	gfd("rbsik",&fdp);
	rb = ring_buffer__new(fd, rbcfn, 0,0);

	//formalite socket falan işleri paket gönderip almak için
	int sockfd;
	struct ifreq ifr;
	struct sockaddr_ll sa;
	unsigned char buffer[14+pds+1];//tam bunu düzenliyodum sen aradın. Aşağıdaki şekilde tanımlıcaz artık
	u char a14(b,pds+1);	//char b[...] (buffer)

	// Create a raw socket
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	///bu perror(char*) ve exit(int?) fonksiyonlarını cidden bilmiyom chatgpt yazdırdı. Gerekirse temizleriz. Zararı yok ama

	// Specify the interface to use
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, "ven1", IFNAMSIZ - 1); // Change "ven1" to your interface name
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
		perror("ioctl");
		close(sockfd);
		exit(1);
	}

	// Prepare the sockaddr_ll structure
	memset(&sa, 0, sizeof(struct sockaddr_ll));
	sa.sll_ifindex = ifr.ifr_ifindex;
	sa.sll_halen = ETH_ALEN;
	sa.sll_protocol = htons(ETH_P_IP);

	// Destination MAC address (broadcast? I am not sure if this meands broadcasr.)
	sa.sll_addr[0] = 0xFF;
	sa.sll_addr[1] = 0xFF;
	sa.sll_addr[2] = 0xFF;
	sa.sll_addr[3] = 0xFF;
	sa.sll_addr[4] = 0xFF;
	sa.sll_addr[5] = 0xFF;

	// Construct Ethernet frame (14 bytes: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes ethertype)
	memset(b, 0, so(b));
	//I just deleted the ethernet frame construction part cuz it receives the frame anyways. My plan is deeper.

	u char f[pcif][pds];	//f(ile): dynamically alloıcayted local array
		
	#define cf for (u char pti=0; pti<pcif; pti++)	for (u char pdi=0; pdi<pds; pdi++)	f[pti][pdi]=ra;	//c(reate) f(ile)

	struct ts t0,t1, t;

	cf;
	p("file data:	");
	for (u char pti=0; pti<pcif; pti++)	for (u char pdi=0; pdi<pds; pdi++)	p("%d ", f[pti][pdi]);
	p("\n");

	tai(t0);
	p("starting to send %hhu files at\t\t\t%ld%ld\n", re, t0.tv_sec, t0.tv_nsec);
	for (u char en=0; en<re; en++)	//for each repetition of experiment
	{
		for (u char pti=0; pti<pcif; pti++)	//for each paocket in the file
		//pti: packet indice
		{
			fa[pti]=0;	//mark the packet pti as not acknowledged
			b[0]=pti;	
			u char pdi=0;	//packet data indice
			for (; pdi<pds; pdi++)	b[1+pdi]=f[pti][pdi];
			p("sent %d\n", b[1]);	//shall remove... For debugging 
			sendto(sockfd, b, sizeof(b), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
		}

		u char cb;	//what is this??
		c:	//c(ontinue)	eğer hala iletildi bilgisi gelmemiş paketler varsa goto c ile döngüden çıkılıyor
		ring_buffer__poll(rb, 0);	//you can optimize the program by setting if not received poll again- like logic, since timeout -last parameter- is 0.	Yani poll sonucu 0 ise aşağıdaki fonksiyona girilmesine gerek yok.
		for (u char pti=0; pti<pcif; pti++)	if (!fa[pti])	//traverse the packets and if you find any non-acknowledged packet...
		{
			b[0]=pti;
			u char pdi=0;
			for (; pdi<pds; pdi++)	b[1+pdi]=f[pti][pdi];
			sendto(sockfd, b, sizeof(b), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));	//...send it again
			goto c;	//Go check if any acks are received
		}
	}
	tai(t1);
	p("transfer has been done by\t\t\t\t%ld%ld\n", t1.tv_sec, t1.tv_nsec);

	e:
	close(sockfd);
	return 0;
}
/*
clang SU.c -o SU -lbpf -fno-builtin
e n1 ./SU 
*/