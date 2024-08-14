// Receiver User-space,
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

// userspace eBPF program includes
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#define CLOCK_TAI 11
static int gfd(char *name, int **fds)
{
	unsigned int id = 0;
	int fd, nb_fds = 0;
	void *tmp;
	int err;

	while (true)
	{
		struct bpf_map_info info = {};
		__u32 len = sizeof(info);

		err = bpf_map_get_next_id(id, &id);
		if (err)
		{
			return nb_fds;
		}

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0)
		{
			goto err_close_fds;
		}

		err = bpf_map_get_info_by_fd(fd, &info, &len);
		if (err)
		{
			goto err_close_fd;
		}

		if (strncmp(name, info.name, BPF_OBJ_NAME_LEN))
		{
			close(fd);
			continue;
		}

		if (nb_fds > 0)
		{
			tmp = realloc(*fds, (nb_fds + 1) * sizeof(int));
			if (!tmp)
			{
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

unsigned char *f;	 // f(ile)
unsigned char *fr; // f(ile) r(eceived)	each element is for marking that a part (packet sized part) of a packet is received or not
char fs, pds, pcif, re, acc;

unsigned char en = 0;
int rbcfn(void *c, void *d, size_t s)
{
	for (unsigned char pti = 0; pti < pcif; pti++)
		if (!fr[pti])
			goto c; //__likely, If there is any packet whose data is not received goto c
	for (unsigned char pti = 0; pti < pcif; pti++)
		fr[pti] = 0;
	en++; // Fully received, prepare for the next repetition of the experiment

	/// şu yujkardaki zıkkınmı neden ring buffer fn.sinde yapıyoruz? Çünkü RK ring buffer'ı öyle bir bombardımana sokuyor ki biz initialization yapamadan sıradaki dosyayı almaya başlıyorlar bunlar. Sonra da fr[*]=1 olduğu için sıkıntı yaşanıyor

	/// e(xperiment) n(umber)

c: // c(ontinue)
	struct timespec t;
	clock_gettime(CLOCK_TAI, &t);
	printf("dereferencing d\n"); // debugging purposes
	printf("%hhu. packet (%hhu) came at \t\t\t%ld%ld\n", *(unsigned char *)d, ((unsigned char *)d)[1], t.tv_sec, t.tv_nsec);

	if (s < pds + 1) // packet data is partial. Just do not receive packet. This functionality can be imroved by receiving partial packets etc. Future weork.
	{
		printf("sending nack\n");
		// bunu copy paste yaptrım yani bu kadar local var tanımlamak falan hepsi overhead. Bunları optimize etmek için global falan yapılabilir
		int sockfd;
		struct ifreq ifr;
		struct sockaddr_ll sa;
		unsigned char buffer[14];

		// Create a raw socket
		if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		{
			perror("socket");
			exit(1);
		}

		// Specify the interface to use
		memset(&ifr, 0, sizeof(struct ifreq));
		strncpy(ifr.ifr_name, "ven1", IFNAMSIZ - 1); // Change "ven1" to your interface name
		if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1)
		{
			perror("ioctl");
			close(sockfd);
			exit(1);
		}

		// Prepare the sockaddr_ll structure
		memset(&sa, 0, sizeof(struct sockaddr_ll));
		sa.sll_ifindex = ifr.ifr_ifindex;
		sa.sll_halen = ETH_ALEN;
		sa.sll_protocol = htons(ETH_P_IP);

		// Destination MAC address...
		sa.sll_addr[0] = 0xFF;
		sa.sll_addr[1] = 0xFF;
		sa.sll_addr[2] = 0xFF;
		sa.sll_addr[3] = 0xFF;
		sa.sll_addr[4] = 0xFF;
		sa.sll_addr[5] = 0xFF;

		// Construct Ethernet frame (14 bytes: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes ethertype)
		memset(buffer, 0, sizeof(buffer));

		// sending nack
		buffer[0] = 1;
		buffer[1] = *(unsigned char *)d;
		sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll));
		close(sockfd);
		return 0;
	}
	for (unsigned char pdi = 0; pdi < pds; pdi++)
		f[((unsigned char *)d)[0] * pcif + pdi] = ((unsigned char *)d)[pdi + 1];
	printf("read packet fully\n"); // debugging

	fr[((unsigned char *)d)[0]] = 1; // mark packet as received
	return 0;
}

int main(int arc, char **ars)
{
	printf("\n");

	if (arc >= 4)
		fs = atoi(ars[1]), pds = atoi(ars[2]), acc = atoi(ars[3]);
	pcif = fs / pds, re = 1;
	unsigned char _fr[pcif];
	fr = _fr;
	for (unsigned char pti = 0; pti < pcif; pti++)
		fr[pti] = 0;
	unsigned char _f[fs];
	f = _f;

	struct ring_buffer *rb;
	int fd = 0, *fdp = &fd;
	gfd("rbrk", &fdp);
	rb = ring_buffer__new(fd, rbcfn, 0, 0);

	for (en = 0; en < re; en++)
	{
		for (unsigned char pti = 0; pti < pcif; pti++)
			fr[pti] = 0;
	c:
		ring_buffer__poll(rb, 0);
		for (unsigned char pti = 0; pti < pcif; pti++)
			if (!fr[pti])
				goto c; // if any packet is not received yet
								// printf("done\n");
	}

	struct timespec t;
	clock_gettime(CLOCK_TAI, &t);
	printf("finished by \t\t\t%ld%ld\n", t.tv_sec, t.tv_nsec);

	printf("file data:	");
	for (unsigned char pti = 0; pti < fs; pti++)
		printf("%hhu ", f[pti]);
	printf("\n");

	/// ya burda datayı random bi şeyler gösteriyor sanırım runtime size array olduğu için problemli bu. Fakat işte debug verileriyle görüyoruz ki veriler doğru paketi falan doğru alıyoruz kernelde ve user space'de. yalnızca okuyamıyoruz.

	return 0;
}
/*
gcc receiver_user.c -o receiver_user.exe -lbpf -fno-builtin
e n2 ./receiver_user.exe
*/