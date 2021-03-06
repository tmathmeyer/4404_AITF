#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <openssl/md5.h>
#include "iputils.h"
#include <inttypes.h>

#define MD5_START_LENGTH 128
#define MD5_FINAL_LENGTH 64

/* Function to print help to the screen
*/
void printHelp(void)
{
	printf("AITF Version 1.0 \n");
	printf("Option Arguments: \n");
	printf("   -t Timeout (requires an integer argument)\n");
	printf("   -s Threshold (requires an integer argument)\n");
	printf("   -h Help\n");
	printf("   -v Verbose\n");
	printf("   -d Debug\n");
	exit(0);
}

//Send a filtering request to the victim gateway
void SendFilteringRequest(struct ip_addr *ip) {
	//Declare Packet
	struct _header_ip *newHeader = malloc(sizeof(struct _header_ip));

	//Make the Source and Dest IPs
	struct ip_addr victim = {.a=192, .b=168, .c=1, .d=195}; //ask Ted what IP is
	struct ip_addr filterDest = {.a=ip->a, .b=ip->b, .c=ip->c, .d=ip->c}; //ask Ted what IP is
	
	//Make IP Header Field = FILTER
	newHeader->protocol = FILTER;
	newHeader->source = victim;
	newHeader->dest = filterDest;
	
}

//Send a filtering request to the victim gateway
void SendFilteringRequest(struct ip_addr *ip) {
	//Declare Packet
	struct _header_ip *newHeader = malloc(sizeof(struct _header_ip));
	struct _tcp_payload *newPayload = malloc(sizeof(struct _tcp_payload));
	uchar *packet = malloc(1000);  //Ultimately this is the packet we want to send

	//Make the Source and Dest IPs
	struct ip_addr victim = {.a=192, .b=168, .c=1, .d=195}; //ask Ted what IP is
	struct ip_addr victimGateway = {.a=192, .b=168, .c=1, .d=195}; //ask Ted what IP is
	
	//Make IP Header Field = FILTER
	newHeader->protocol = FILTER;
	newHeader->source = victim;
	newHeader->dest = victimGateway;
	
	//Put IP address in payload
	struct _tcp_payload payload;
	unsigned char *data = malloc(100);
	sprintf(data, "%s.%s.%s.%s", ip.a, ip.b, ip.c, ip.d);
	payload.data =  data;
	payload.size = (uint32_t) sizeof(data);
	//Send packet to Victim gateway
	
}

int main (int argc, char **argv)
{
	int timeout = 1;
	int threshold = 80;
	int hFlag = 0; // help flag 
	int vFlag = 0; // verbose flag
	int dFlag = 0; // debug flag
	char *cvalue = NULL;
	int c;
	
	//int opterr = 0;
	while ((c = getopt (argc, argv, "t:s:hvd")) != -1)
    switch (c)
	{
		case 't':
		{
			timeout = atoi(optarg);
			printf("Changed timeout to %d\n", timeout);
			break;
		}
		case 's':
		{
			threshold = atoi(optarg);
			printf("Changed threshold to %d\n", threshold);
			break;
		}
		case 'h':
		{
			printHelp();
			break;
		}
		case 'v':
		{
			vFlag = 1;
			printf("Verbose flag set \n");
			break;
		}
		case 'd':
		{
			dFlag = 1;
			printf("Debug flag set \n");
			break;
		}
		case '?':
		{
			fprintf (stderr, "Unknown option.\n");
			printHelp();
		}
		default:
		{
			printHelp();
		}
		return 0;
	}
	
	uint64_t ip = 5;
	uint64_t salt = 2;
	uint64_t hash = 7;
    //calcMD5(&hash, &salt, &ip);
	//printf("I WORRK. Here is my hash %" PRIu64 "\n", hash);
}
