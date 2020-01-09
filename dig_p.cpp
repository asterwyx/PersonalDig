#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


#define DNS_SERVER "127.0.0.53"	// Local DNS server
#define SERV_PORT 53			// Standard DNS query port
#define A 1						// A record type
#define NS 2					// NS record type
#define CNAME 5					// CNAME record type
#define INTERNET_DATA 1			// Internet query class
#define MAX_SIZE 4096

static short conversationId = 0;
int setQueryMsg(char *domainName, unsigned char *buffer, int queryType, int queryClass);
int parseResponse(unsigned char *response, int responseLen);			// Parse DNS response


#pragma (push,1)
typedef struct dns_header {
	unsigned short conversation_id;  // Conversation identifier
	unsigned short qr_flag:1;     // Query or response flag, 0 for query, 1 for response
	unsigned short opcode_flag:4; // Operation code flag, 0 for standard query, 1 for reversal query, 2 for server status request
	unsigned short aa_flag:1;     // Authoritive answer, only response will set this
	unsigned short tc_flag:1;     // 1 for truncated, 0 for not
	unsigned short rd_flag:1;     // Desire recursive query
	unsigned short ra_flag:1;     // Whether recursive query is available
	unsigned short rcode_flag:4;  // Return code, 0 for success, 3 for name error, 2 for server error
	unsigned short qd_count;			// Queries count
	unsigned short an_count;			// Answers count
	unsigned short ns_count;			// Number of name server resource records
	unsigned short ar_count;			// Number of resource records in the additional records section
} DNS_HEADER;
#pragma (pop)

typedef struct question {
	unsigned short qtype;
	unsigned short qclass;
	unsigned char *domainName;
} QUESTION;

typedef struct resource_record {
	unsigned char *name;
	unsigned short type;
	unsigned short _class;
	unsigned short data_length;
	unsigned int ttl;	// Time to live
	unsigned char *data;	// Data buffer
} RES_RECORD;

typedef struct query {
	DNS_HEADER header;
	QUESTION question_sec;
} QUERY;





// Main function
int main(int argc, char *argv[])
{
	char queryDomainName[MAX_SIZE] = "localhost";
	if (argc > 1)
	{
		strcpy(queryDomainName, argv[argc - 1]);
	}
	// Try to query from DNS server set by /etc/resolv.conf
	// First Mannuly set server
	unsigned char queryMsg[MAX_SIZE];
	unsigned char responseMsg[MAX_SIZE];
	// Set query message
	int requestLen = setQueryMsg(queryDomainName, queryMsg, A, INTERNET_DATA);		// Query A record of domain name
	// For debugging, print request
	for (int i = 0; i < requestLen; i++)
	{
		printf("%x ", queryMsg[i]);
	}
	printf("\n");
	
	struct sockaddr_in dest_addr;
	memset(&dest_addr, 0, sizeof(struct sockaddr_in));
	dest_addr.sin_addr.s_addr = inet_addr(DNS_SERVER);
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(SERV_PORT);
	int sendSock = socket(PF_INET, SOCK_DGRAM, 0);
	int sentSize = sendto(sendSock, queryMsg, requestLen, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
	if (sentSize > 0)
	{
		printf("Successfully send queries!\n");
		printf("Sent size: %d\n", sentSize);
	}
	else
	{
		printf("Failed!\n");
	}
	int responseLen = recv(sendSock, responseMsg, MAX_SIZE, 0);
	printf("Received size: %d\n", responseLen);	
	// For debugging, print reponse
	for (int i = 0; i < responseLen; i++)
	{
		printf("%x ", responseMsg[i]);
	}
	printf("\n");
	return 0;
}


int setQueryMsg(char *domainName, unsigned char *buffer, int queryType, int queryClass)
{
	if (domainName == NULL || buffer == NULL)
	{
		perror("NULL pointer");
		return 0;
	}

	// Temporary set 0
	buffer[0] = 0x00;
	buffer[1] = 0;
	buffer[2] = 0x01;			// Represent queryMsg
	buffer[3] = 0;				
	buffer[4] = 0;
	buffer[5] = 1;				// One query

	// All set 0
	for (int i = 6; i < 12; i++)
	{
		buffer[i] = 0;
	}
	
	// Set domain name
	// Split domain name
	int cursor = 0;
	unsigned char *name = buffer + 12;
	unsigned char *counter = name;
	while (domainName[0] != '\0')
	{
		for (*counter = 0; domainName[cursor] != '.' && domainName[cursor] != '\0'; (*counter)++)
		{
			name[cursor + 1] = domainName[cursor];
			cursor++;
		}
		// Set counter
		counter = name + 1 + cursor;
		if (domainName[cursor] == '\0')
		{
			cursor++;
			break;
		}
		else
		{
			cursor++;
		}
	}
	name[cursor++] = 0;			// Set end of buffer
	// Now buffer has correct data and form
	name[cursor] = 0;
	name[cursor + 1] = queryType;	// Set query type
	name[cursor + 2] = 0;
	name[cursor + 3] = queryClass;	// Set query class
	return cursor + 16;
}


