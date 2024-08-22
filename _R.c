//Receiver the total user-space implemeentation
#include "c.h"
#include "us.h"

#include <time.h>
#define tai(var) clock_gettime(CLOCK_TAI, &var)
#define ts timespec

#define ra (rand()%256)
#define p printf

#define BUFFER_SIZE 1024

int main() {
	int sockfd;
	struct sockaddr_in6 dest_addr;
	const char *ipv6_addr_str = "fe80::5054:ff:fee8:9be9";
	int port = 1111;
	struct sockaddr_in6 addr;
	unsigned char buffer[BUFFER_SIZE];
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

	printf("Waiting for UDP packets on port 1111...\n");

	ssize_t len = recvfrom(sockfd, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&addr, &addr_len);
	char fs=buffer[0], pds=buffer[1], pcif,re, acc=buffer[2];
	pcif = fs/pds, re=1;

	u char f[pcif][pds];
	u char fr[pcif];

	#define sebl (1+acc)
	#define rebl (1+pds)
	u char seb[sebl],reb[rebl];	memset(seb, 0, sizeof(seb));	memset(reb, 0, sizeof(reb));
		
	for (u char en=0; en<re; en++)
	{
		for (u char pti=0; pti<pcif; pti++)	fr[pti]=0;
		u char ptc=0;	//reset ptc to be able to send partyaial cumulative acks
		u short int enc=0;
		c:
		ssize_t len = recvfrom(sockfd, reb, sizeof(reb), 0, (struct sockaddr *)&addr, &addr_len);

		if (len==-1)	p("recvfrom error.\n");
		else if (len)
		{
			p("debug sizeof(reb) %zu\n", len);
					p("debug: accessed reb");
					for (u char *ucp = reb+0; ucp<reb+sizeof(reb); ucp++)	p(" %hhu", *ucp);
					p("\n");
			struct ts t;	tai(t);
			p("%hhu. packet came at \t\t\t\t%ld%ld\n", reb[0], t.tv_sec, t.tv_nsec);
			seb[0+1+seb[0]] = reb[0];
			ptc++, seb[0]++;
			if (seb[0] >= acc || ptc==pcif)	//sending cumulative ack with dynamic size
			{
				p(" cumulative ack ssent\n");
				sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
				seb[0]=0;
			}
			for (u char pdi=0; pdi<pds; pdi++)	f[reb[0]][pdi]=reb[1+0+pdi];
			fr[reb[0]] = 1;
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
/* 
	// Receive UDP packets
	while (1) {
		ssize_t len = recvfrom(sockfd, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&addr, &addr_len);
		if (len < 0) {
			perror("recvfrom");
			close(sockfd);
			return 1;
		}

		printf("Received %zu bytes:", len);
		for (unsigned char pti=0; pti<len; pti++)	printf(" %hhu", buffer[pti]);
		printf("\n");
	}
 */
	// Close the socket (not reachable in this example, but important in a real application)
	close(sockfd);

	return 0;
}
/*-fsched-dep-count-heuristic
gcc _R.c -o _R
sudo ip link set dev ens3 xdpgeneric off
sudo ./_R 
*/