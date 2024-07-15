//Receiver the total user-space implemeentation

#define _POSIX_C_SOURCE 199309L	//for use of TAI clock

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if.h>

#include <time.h>
#define tai(var) clock_gettime(CLOCK_TAI, &var)
#define ts timespec

#include "c.h"

#define p printf
#define a14(na, si) na[(si<14) ? 14 : (si)]	//create a array whose size is max(14, si) with na(me)

int main(int arc, char** ars)
{
	p("\n");

	char fs,pds,pcif,re,acc;
	if (arc>=4)	fs = atoi(ars[1]), pds = atoi(ars[2]), acc = atoi(ars[3]);
	pcif = fs/pds, re=1;

	u char f[pcif][pds];
	u char fr[pcif];

	int sockfd;
	struct ifreq ifr;
	struct sockaddr_ll sa;
	unsigned char a14(reb, 100), a14(seb, acc+1);	//se(nd) / re(ceive) b(uffer) 

	// Create a raw socket
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	// Specify the interface to listen on
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, "eth2", IFNAMSIZ - 1); // Change "eth2" to your interface name
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

	// Destination MAC address (example)
	sa.sll_addr[0] = 0xFF;
	sa.sll_addr[1] = 0xFF;
	sa.sll_addr[2] = 0xFF;
	sa.sll_addr[3] = 0xFF;
	sa.sll_addr[4] = 0xFF;
	sa.sll_addr[5] = 0xFF;

	// Construct Ethernet frame (14 bytes: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes ethertype)
	memset(seb, 0, sizeof(seb));
	memset(reb, 0, sizeof(reb));

	printf("Listening on interface %s\n", ifr.ifr_name);
	
	for (u char en=0; en<re; en++)
	{
		for (u char pti=0; pti<pcif; pti++)	fr[pti]=0;
		u char ptc=0;	//reset ptc to be able to send partyaial cumulative acks
		c:
		ssize_t num_bytes = recvfrom(sockfd, reb, sizeof(reb), 0, NULL, NULL);
		
			p("debug %zu\n", sizeof(reb));
		if (num_bytes==-1)	p("recvfrom error.\n");
		if (num_bytes)
		{
			struct ts t;	tai(t);
			p("debug %zu\n", sizeof(reb));
					p("debug: accessed reb");
					for (u char *ucp=reb; ucp<reb+100; ucp++)	p(" %hhu", *ucp);
					p("\n");
			p("%hhu. packet came at \t\t\t\t%ld%ld\n", reb[0], t.tv_sec, t.tv_nsec);
			seb[1+seb[0]] = reb[0];
			ptc++, seb[0]++;
			if (seb[0] >= acc || ptc==pcif)	//sending cumulative ack with dynamic size
			{
				p(" cumulative ack ssent\n");
				sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
				seb[0]=0;
			}
			for (u char pdi=0; pdi<pds; pdi++)	f[reb[0]][pdi]=reb[1+pdi];
			fr[reb[0]] = 1;
		}
		for (u char pti=0; pti<pcif; pti++)	if (!fr[pti])	goto c;
		
		p("file info:	");
		for (u char pti=0; pti<pcif; pti++)	for (u char pdi=0; pdi<pds; pdi++)	p("%d ", f[pti][pdi]);
		p("\n");
	}

	struct ts t;	tai(t);
	p("experiment finished at \t\t\t%ld%ld\n", t.tv_sec, t.tv_nsec);

	p("\n");
	close(sockfd);
	return 0;
}
/*
sudo ip link set dev eth2 xdpgeneric off
clang _R.c -o _R -lbpf
sudo ./_R 
*/
