//Receiver the total user-space implemeentation
#include "us.h"

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

	/* Construct frame	<size"explanation * size"explanation" * ...>
	seb = <1"network-space header" * 1"packet indice" * pcif"data">
	reb = <1"network-space header" * 1"ack length (acl)" * acc"packet indice array">
	*/
	#define sebhs 54	//send buffer header size
	#define sebl (sebhs+1+pcif)
	#define rebl (sebhs+1+acc)
	u char seb[sebl], reb[rebl];//todo
	memset(seb, 0, sizeof(seb));	memset(reb, 0, sizeof(reb));
	#define nwsh 253

	struct ethhdr *enh = seb;

	enh->h_proto = 0x86dd;

	enh->h_source[0] = 0x52;
	enh->h_source[1] = 0x54;
	enh->h_source[2] = 0x00;
	enh->h_source[3] = 0x19;
	enh->h_source[4] = 0x38;
	enh->h_source[5] = 0x30;

	enh->h_dest[6+0] = 0xff;
	enh->h_dest[6+1] = 0xff;
	enh->h_dest[6+2] = 0xff;
	enh->h_dest[6+3] = 0xff;
	enh->h_dest[6+4] = 0xff;
	enh->h_dest[6+5] = 0xff;
	
	struct ip6_hdr *ip6h = (struct ip6_hdr *) (seb+14);
	ip6h->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(6<<28);
	ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen = htonl(sebl);
	ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt = 253;
	ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim = 255;

	seb[22+0] = 0xfe;
	seb[22+1] = 0x80;
	seb[22+8] = 0x50;
	seb[22+9] = 0x54;
	seb[22+10] = 0x00;
	seb[22+11] = 0xff;
	seb[22+12] = 0xfe;
	seb[22+13] = 0x19;
	seb[22+14] = 0x38;
	seb[22+15] = 0x30;

	seb[38+0] = 0xfe;
	seb[38+1] = 0x80;
	seb[38+8] = 0x50;
	seb[38+9] = 0x54;
	seb[38+10] = 0x00;
	seb[38+11] = 0xff;
	seb[38+12] = 0xfe;
	seb[38+13] = 0xe8;
	seb[38+14] = 0x9b;
	seb[38+15] = 0xe9;

	// Create a raw socket
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	// Specify the interface to listen on
	#define ifa "ens3"	//interface
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifa, IFNAMSIZ - 1); // Change "eth2" to your interface name
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

	printf("Listening on interface %s\n", ifr.ifr_name);
	
	for (u char en=0; en<re; en++)
	{
		seb[1] = 0;
		for (u char pti=0; pti<pcif; pti++)	fr[pti]=0;
		u char ptc=0;	//reset ptc to be able to send partyaial cumulative acks
		u short int enc=0;
		c:
		ssize_t num_bytes = recvfrom(sockfd, reb, sizeof(reb), 0, NULL, NULL);
		if (num_bytes==-1)	p("recvfrom error.\n");
		if (num_bytes)
		{
			p("debug %zu\n", sizeof(reb));
					p("debug: accessed reb");
					for (u char *ucp=reb; ucp<reb+sizeof(reb); ucp++)	p(" %hhu", *ucp);
					p("\n");
			struct ts t;	tai(t);
			p("%hhu. packet came at \t\t\t\t%ld%ld\n", reb[1], t.tv_sec, t.tv_nsec);
			seb[2+seb[1]] = reb[1];
			ptc++, seb[1]++;
			if (seb[1] >= acc || ptc==pcif)	//sending cumulative ack with dynamic size
			{
				p(" cumulative ack ssent\n");
				sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
				seb[1]=0;
			}
			for (u char pdi=0; pdi<pds; pdi++)	f[reb[1]][pdi]=reb[2+pdi];
			fr[reb[1]] = 1;
		}
		//else if (num_bytes)	p("%hhu, %d\n", reb[0], num_bytes);
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
/*-fsched-dep-count-heuristic
sudo ip link set dev eth2 xdpgeneric off
gcc _R.c -o _R
sudo ./_R 
*/