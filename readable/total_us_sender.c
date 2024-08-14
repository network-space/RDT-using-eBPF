//Sender total userspace (for comparison)
//No nacks
/*frames to be sent and received are as follows: (<size"explanation" * size"explanation" * ...>)
seb = <1"packet indice" * pcif"data">
reb = <1"ack length (acl)" * acc"packet indice array">
*/
#include "common.h"
#include "userspace.h"
#include <time.h>


unsigned char *fa;
int main(int arc, char** ars)
{
	int sockfd;
	struct sockaddr_in6 dest_addr;
	const char *ipv6_addr_str = "fe80::5054:ff:fe19:3830";
	const char *message = "Hello, UDP over IPv6!";
	int port = 1111;

	char fs,pds,pcif,re,acc;
	if (arc>=4)	fs = atoi(ars[1]), pds = atoi(ars[2]), acc = atoi(ars[3]);
	pcif = fs/pds, re=1;
	unsigned char _fa[pcif];	fa=_fa;

	srand(time(0));
	#define sebl (1+pds)
	#define rebl (1+acc)
	unsigned char seb[sebl],reb[rebl];	memset(seb, 0, sizeof(seb));	memset(reb, 0, sizeof(reb));

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
	dest_addr.sin6_port = htons(port);

	// Convert IPv6 address from text to binary
	if (inet_pton(AF_INET6, ipv6_addr_str, &dest_addr.sin6_addr) != 1) {
		perror("inet_pton");
		close(sockfd);
		return 1;
	}

	//send metadata about file to be sent, so _R is not a variadic executable
	unsigned char pt[3] = {fs,pds,acc};	//	pt[0]=fs, pt[1]=pds, pt[2]=acc;

	// Send the UDP packet
	if (sendto(sockfd, pt, sizeof(pt), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
		perror("sendto");
		close(sockfd);
		return 1;
	}

	printf("UDP packet sent to %s:%d\n", ipv6_addr_str, port);
	return 0;

	struct timespec t0,t1, t;

	unsigned char f[pcif][pds];
	#define cf for (unsigned char pti=0; pti<pcif; pti++)	for (unsigned char pdi=0; pdi<pds; pdi++)	f[pti][pdi]=RANDOM_BYTE, fa[pti]=0;
	cf;
	printf("file info:	");
	for (unsigned char pti=0; pti<pcif; pti++)	for (unsigned char pdi=0; pdi<pds; pdi++)	printf("%d ", f[pti][pdi]);
	printf("\n");

	clock_gettime(CLOCK_TAI, &t0);
	printf("starting to send %hhu files at\t\t\t%ld%ld\n", re, t0.tv_sec, t0.tv_nsec);
	for (unsigned char en=0; en<re; en++)
	{
		for (unsigned char pti=0; pti<pcif; pti++)
		{
			fa[pti]=0;
			seb[0]=pti;
			unsigned char pdi=0;
			for (; pdi<pds; pdi++)	seb[0+1+pdi]=f[pti][pdi];
			sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		}

		c:
		//receive acks
		socklen_t addr_len = sizeof(addr);
		ssize_t num_bytes = recvfrom(sockfd, reb, sizeof(reb), 0, (struct sockaddr *)&addr, &addr_len);
		//if (num_bytes==-1)	printf("recvfrom error.\n");
		printf("Received %zu bytes:", num_bytes);
		for (unsigned char pti=0; pti<num_bytes; pti++)	printf(" %hhu", reb[pti]);
		printf("\n");

		if (num_bytes)	for (unsigned char aci=0; aci<reb[0]; aci++)	fa[reb[0+1+aci]] = 1;	//, printf("received, %hhu\n", *reb);

		for (unsigned char pti=0; pti<pcif; pti++)	if (!fa[pti])
		{
			seb[0]=pti;
			unsigned char pdi=0;
			for (; pdi<pds; pdi++)	seb[0+1+pdi]=f[pti][pdi];
			sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
			//printf("resending\n");
			goto c;
		}
	}
	clock_gettime(CLOCK_TAI, &t1);
	printf("experiment done by \t\t\t\t%ld%ld\n", t1.tv_sec, t1.tv_nsec);

	e:
	// Close the socket
	close(sockfd);
	return 0;
}
/*
sudo ip link set dev ens3 xdpgeneric off
gcc total_us_sender.c -o total_us_sender
sudo ./total_us_sender
*/