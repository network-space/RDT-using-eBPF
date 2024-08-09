//Sender total userspace (for comparison)
//No nacks
#include "us.h"

#include <time.h>
#define tai(var) clock_gettime(CLOCK_TAI, &var)
#define ts timespec

#include "c.h"

#define ra (rand()%256)
#define p printf
#define a14(na, si) na[(si<14) ? 14 : (si)]	//create a array whose size is max(14, si) with na(me)

u char *fa;
int rbsfn(void*c, void*d, size_t s)
{
	fa[*(u char *)d]=1;
	return 0;
}

int main(int arc, char** ars)
{
	p("\n");

	char fs,pds,pcif,re,acc;
	if (arc>=4)	fs = atoi(ars[1]), pds = atoi(ars[2]), acc = atoi(ars[3]);
	pcif = fs/pds, re=1;
	u char _fa[pcif];	fa=_fa;

	srand(time(0));

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
	//unsigned char a14(seb,sebhs+1+pcif), a14(reb, 2+acc);	//se(nd) / re(ceive) b(uffer)
	u char seb[sebl], reb[rebl];//todo
	memset(seb, 0, sizeof(seb));	memset(reb, 0, sizeof(reb));
	#define nwsh 253

	struct ethhdr *enh = seb;

	enh->h_proto = 0x86dd;

	enh->h_source[0] = 0x52;
	enh->h_source[1] = 0x54;
	enh->h_source[2] = 0x00;
	enh->h_source[3] = 0xe8;
	enh->h_source[4] = 0x9b;
	enh->h_source[5] = 0xe9;

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
	seb[22+13] = 0xe8;
	seb[22+14] = 0x9b;
	seb[22+15] = 0xe9;

	seb[38+0] = 0xfe;
	seb[38+1] = 0x80;
	seb[38+8] = 0x50;
	seb[38+9] = 0x54;
	seb[38+10] = 0x00;
	seb[38+11] = 0xff;
	seb[38+12] = 0xfe;
	seb[38+13] = 0x19;
	seb[38+14] = 0x38;
	seb[38+15] = 0x30;

	// Create a raw socket
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		perror("socket");
		exit(1);
	}

	// Specify the interface to use
	#define ifa "ens3"	//interface
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifa, IFNAMSIZ - 1);
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


	u char f[pcif][pds];
		
	#define cf for (u char pti=0; pti<pcif; pti++)	for (u char pdi=0; pdi<pds; pdi++)	f[pti][pdi]=ra, fa[pti]=0;

	struct ts t0,t1, t;

	cf;
	p("file info:	");
	for (u char pti=0; pti<pcif; pti++)	for (u char pdi=0; pdi<pds; pdi++)	p("%d ", f[pti][pdi]);
	p("\n");

	tai(t0);
	p("starting to send %hhu files at\t\t\t%ld%ld\n", re, t0.tv_sec, t0.tv_nsec);
	for (u char en=0; en<re; en++)
	{
		for (u char pti=0; pti<pcif; pti++)
		{
			fa[pti]=0;
			seb[sebhs]=pti;
			u char pdi=0;
			for (; pdi<pds; pdi++)	seb[sebhs+1+pdi]=f[pti][pdi];
			sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
		}

		c:
		//receive acks
		ssize_t num_bytes = recvfrom(sockfd, reb, sizeof(reb), 0, NULL, NULL);
		if (num_bytes==-1)	p("recvfrom error.\n");
		if (num_bytes)	for (u char aci=0; aci<reb[sebhs]; aci++)	fa[reb[sebhs+1+aci]] = 1, p("received, %hhu\n", *reb);

		for (u char pti=0; pti<pcif; pti++)	if (!fa[pti])
		{
			seb[sebhs]=pti;
			u char pdi=0;
			for (; pdi<pds; pdi++)	seb[sebhs+1+pdi]=f[pti][pdi];
			sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
			p("resending\n");
			goto c;
		}
	}
	tai(t1);
	p("experiment done by \t\t\t\t%ld%ld\n", t1.tv_sec, t1.tv_nsec);

	e:
	close(sockfd);
	return 0;
}
/*
sudo ip link set dev eth0 xdpgeneric off
gcc _S.c -o _S
sudo ./_S 
*/