//userspace
#define _POSIX_C_SOURCE 199309L	//for use of TAI clock
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

//network send/receive...
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>