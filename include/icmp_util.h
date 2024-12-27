#ifndef _ICMP_UTIL_
#define _ICMP_UTIL_

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>

#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

#include <asm/byteorder.h>

// Ethernet header
struct ethheader {
	char dest[6];    // 48 bit
	char source[6];  // 48 bit
	short type;     // 16 bit
};

// IP header
struct ipheader {
	// https://stackoverflow.com/questions/42840636/difference-between-struct-ip-and-struct-iphdr
	#if defined(__LITTLE_ENDIAN_BITFIELD)
        char    ihl:4,
                version:4;
    #elif defined (__BIG_ENDIAN_BITFIELD)
        char    version:4,
                ihl:4;
    #else
        #error  "Please fix <asm/byteorder.h>"
    #endif
	char tos; // 8 bit
	short tot_len; // 16 bit
	short id; // 16 bit
	short frag_off; // 16 bit
	char ttl; // 8 bit
	char protocol; // 8 bit
	short checksum; // 16 bit
	int saddr; // 32 bit
	int daddr; // 32 bit
};

// ICMP header
struct icmpheader {
	char type; // 8 bit
	char code; // 8 bit
	short checksum; // 16 bit
	short id; // 16 bit
	short sequence; // 16 bit
};


void get_mac_address(const char *device, unsigned char* mac);
void get_ip_address(const char *device, unsigned char* ip_address);

unsigned short calculate_checksum(void *b, int len);

#endif