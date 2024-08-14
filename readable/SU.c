//Sender Userspace
/*frames to be sent and received are as follows: (<size"explanation" * size"explanation" * ...>)
seb = <1"packet type" * 1"packet indice" * pcif"data">
packet type: 0 for metadata, 1 for data
*/
#include "c.h"
#include "us.h"

//userspace eBPF program includes
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <time.h>
#define tai(var) clock_gettime(CLOCK_TAI, &var)	//TAI clcok get time
#define ts timespec


#define ra (rand()%256)	//random byte
#define p printf
#define so sizeof

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
u char mdr;	//metadata received
int rbcfn(void*c, void*d, size_t s)	//r(ing) b(uffer) c(onsuming) f(unctio)n
//c(ontext): ne olduğunu bimiyom kullanmıyıoz
//d(ata) is array of s(ize) bytes
{	//ring buffer'a veri geldiği poll fonksiyonunca anlaşıldıkça bu fonksiyon çağrılıyuor. Ya da ringbuffernew gibi bir fn. ile ring buffer oluşturukuynca? Wmin değilim.
	if (s==1)
	{
		p("size low\n");
	}	
	switch (((u char *)d)[0])
	{
		case 0:	//metadata ack
			p("md ack%hhu\n");
			mdr=1;
			break;
		case 2:	//ack
			p("ack%hhu\n", ((u char *)d)[1] );
			fa[((u char *)d)[1]]=1;
			break;
		case 3:	//nack
			p("nack%hhu\n", ((u char *)d)[1] );
			fa[((u char *)d)[1]]=0;
	}
	return 0;
}

int main(int arc, char** ars)	//argumenty callable
//arc: ar(gument) c(ount)
//ars: ar(gument)s
{	//call it like below.
//SU fs pds acc
//so for example SU 32 4 2 means Each file consists of 32 bytes, to be sent 4 bytes per packet, a single ack can include at most 2 packets' ack
	int sockfd;
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
	struct sockaddr_in6 dest_addr;
	// Create a socket
	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	// Zero out the address structure
	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any; // Bind to all interfaces
	addr.sin6_port = htons(1111); // Bind to port 

	// Bind the socket
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(sockfd);
		return 1;
	}

	// Zero out the destination address structure
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin6_family = AF_INET6;
	dest_addr.sin6_port = htons(1111);

	// Convert IPv6 address from text to binary
	if (inet_pton(AF_INET6, "fe80::5054:ff:fe19:3830", &dest_addr.sin6_addr) != 1) {
		perror("inet_pton");
		close(sockfd);
		return 1;
	}
	
	while (mdr)	//send metadata about file to be sent, so _R is not a variadic executable
	{
		u char md[4] = {0,fs,pds,acc};	//metadata
		if (sendto(sockfd, md, sizeof(md), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
			perror("sendto");
			close(sockfd);
			return 1;
		}
		ring_buffer__poll(rb, 0);
	}
	// Send the UDP packet
	p("metadata sent\n");


	#define sebl (2+pds)
	#define rebl (1+acc)
	u char seb[sebl],reb[rebl];	memset(seb, 0, sizeof(seb));	memset(reb, 0, sizeof(reb));
	seb[0]=1;	//data packet

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
			seb[1]=pti;	
			u char pdi=0;	//packet data indice
			for (; pdi<pds; pdi++)	seb[2+pdi]=f[pti][pdi];
			p("sent %d\n", seb[2]);	//shall remove... For debugging 
			sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		}

		u char cb;	//what is this??
		c:	//c(ontinue)	eğer hala iletildi bilgisi gelmemiş paketler varsa goto c ile döngüden çıkılıyor
		ring_buffer__poll(rb, 0);	//you can optimize the program by setting if not received poll again- like logic, since timeout -last parameter- is 0.	Yani poll sonucu 0 ise aşağıdaki fonksiyona girilmesine gerek yok.
		for (u char pti=0; pti<pcif; pti++)	if (!fa[pti])	//traverse the packets and if you find any non-acknowledged packet...
		{
			seb[1]=pti;
			u char pdi=0;
			for (; pdi<pds; pdi++)	seb[2+pdi]=f[pti][pdi];
			sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));	//...send it again
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
gcc SU.c -o SU -lbpf
sudo ./SU 1 1 1

sudo ./SU {file_size} {pck_data_size} {ack_cum}
*/