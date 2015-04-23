#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <openssl/md5.h>


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

void getHashData(uint64_t *salt, uint64_t *ip)
{
	
	
	
}

/*
	* Function to calculate MD5 hash for salt and IP
*/
void calcMD5(uint64_t *hash, uint64_t *salt, uint64_t *ip)
{
    unsigned char input[16];
    unsigned char temp_result[16];
    *((uint64_t *)input) = *salt;
    *((uint64_t *)(input+8)) = *hash;
	MD5(input, 16, temp_result);
	*hash = *((uint64_t *) temp_result) ^ *((uint64_t *)(temp_result+8));

	if(dFlag)
	{
		printf("Hash: %llu\n", *hash);
	}
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
	
	opterr = 0;
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
	
	uint64_t ip;
	uint64_t salt;
	
	getHashData(&salt, &ip);
	
	uint64_t hash;
    calcMD5(&hash, &salt, &ip);
}
