//Receiver User-space,
#include "us.h"

//userspace eBPF program includes
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <time.h>
#define tai(var) clock_gettime(CLOCK_TAI, &var)
#define ts timespec

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

#include "c.h"

#define p printf

u char *f;	//f(ile)
u char *fr;	//f(ile) r(eceived)	each element is for marking that a part (packet sized part) of a packet is received or not
char fs,pds,pcif,re,acc;

#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

u char mdr=0;	//metadata received
u char en=0;
int rbcfn(void*c, void*d, size_t s)
{
	for (u char pti=0; pti<pcif; pti++)	if (!fr[pti])	goto c;	//__likely, If there is any packet whose data is not received goto c
	for (u char pti=0; pti<pcif; pti++)	fr[pti]=0; en++;	//Fully received, prepare for the next repetition of the experiment

	///şu yujkardaki zıkkınmı neden ring buffer fn.sinde yapıyoruz? Çünkü RK ring buffer'ı öyle bir bombardımana sokuyor ki biz initialization yapamadan sıradaki dosyayı almaya başlıyorlar bunlar. Sonra da fr[*]=1 olduğu için sıkıntı yaşanıyor

	///e(xperiment) n(umber)
	
	c:	//c(ontinue)

	switch (((u char *)d)[0])
	{
		case 0:	//metadata
			if (s < 4)	break;
			mdr=1;
			//p("md %hhu %hhu %hhu\n", ((u char *)d)[1], ((u char *)d)[2], ((u char *)d)[3] );
			fs = ((u char *)d)[1];
			pds = ((u char *)d)[2];
			acc = ((u char *)d)[3];
			pcif = fs/pds;
			break;
		case 1:	//data
			//p("packet %hhu\n", ((u char *)d)[1] );
			struct ts t;	tai(t);
			//p("dereferencing d\n");	//debugging purposes
			//p("%hhu. packet (%hhu) came at \t\t\t%ld%ld\n", ((u char *)d)[1], ((u char *)d)[2], t.tv_sec, t.tv_nsec);
			if (s < pds+1)	//packet data is partial. Just do not receive packet. This functionality can be imroved by receiving partial packets etc. Future weork.
			{
				p("sending nack\n");
				//bunu copy paste yaptrım yani bu kadar local var tanımlamak falan hepsi overhead. Bunları optimize etmek için global falan yapılabilir 
				int sockfd;
				struct sockaddr_in6 dest_addr;
				const char *ipv6_addr_str = "fe80::5054:ff:fee8:9be9";
				int port = 1111;
				struct sockaddr_in6 addr;
				socklen_t addr_len = sizeof(addr);

				// Create a socket
				sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
				if (sockfd < 0) {
					perror("socket");
					return 1;
				}

				// Zero out the address structure
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
				dest_addr.sin6_port = htons(port);

				// Convert IPv6 address from text to binary
				if (inet_pton(AF_INET6, ipv6_addr_str, &dest_addr.sin6_addr) != 1) {
					perror("inet_pton");
					close(sockfd);
					return 1;
				}

				//sending nack
				u char seb[2] = {3, ((u char *)d)[1]};
				sendto(sockfd, &seb, 1, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
				close(sockfd);
				return 0;
			}
			u char pti = ((u char *)d)[1];	//packet indice
			for (u char pdi=0; pdi<pds; pdi++)	f[pti*pcif + pdi] = ((u char *)d)[pdi+2];

			//p("marked\n");
			fr[pti] = 1;	//mark packet as received
	}
	return 0;
}

int main(int arc, char** ars)
{
	p("\n");

	//if (arc>=4)	fs = atoi(ars[1]), pds = atoi(ars[2]), acc = atoi(ars[3]);
	re=1;
	u char _fr[pcif];	fr=_fr;
	for (u char pti=0; pti<pcif; pti++)	fr[pti]=0;
	u char _f[fs];	f=_f;

	struct ring_buffer *rb;
	int fd=0, *fdp=&fd;
	gfd("rbrk",&fdp);
	rb = ring_buffer__new(fd, rbcfn, 0,0);


	int sockfd;
	struct sockaddr_in6 dest_addr;
	const char *ipv6_addr_str = "fe80::5054:ff:fee8:9be9";
	int port = 1111;
	struct sockaddr_in6 addr;
	socklen_t addr_len = sizeof(addr);

	// Create a socket
	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	// Zero out the address structure
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
	dest_addr.sin6_port = htons(port);

	// Convert IPv6 address from text to binary
	if (inet_pton(AF_INET6, ipv6_addr_str, &dest_addr.sin6_addr) != 1) {
		perror("inet_pton");
		close(sockfd);
		return 1;
	}

	for (en=0; en<re; en++)
	{
		p("done, %hhu\n", en);
		p("waiting for md.\n");
		while (!mdr)	ring_buffer__poll(rb, 0);
		p("md receieved\n");

		for (u char pti=0; pti<pcif; pti++)	fr[pti]=0;
		c:
		ring_buffer__poll(rb, 0);
		for (u char pti=0; pti<pcif; pti++)	if (!fr[pti])	goto c;	//if any packet is not received yet
		p("done, %hhu\n", en);
	}

	struct ts t;
	tai(t);
	p("finished by \t\t\t%ld%ld\n", t.tv_sec, t.tv_nsec);
	
	p("file data:	");
	for (u char bi=0; bi<fs; bi++) p("%hhu ", f[bi]);
	p("\n");

	///ya burda datayı random bi şeyler gösteriyor sanırım runtime size array olduğu için problemli bu. Fakat işte debug verileriyle görüyoruz ki veriler doğru paketi falan doğru alıyoruz kernelde ve user space'de. yalnızca okuyamıyoruz.
	
	return 0;
}
/*
gcc RU.c -o RU -lbpf
sudo ./RU 
*/