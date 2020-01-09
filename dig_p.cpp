#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>


#define DNS_SERVER "127.0.0.53"	// Local DNS server
#define SERV_PORT 53			// Standard DNS query port
#define A 1						// A record type
#define NS 2					// NS record type
#define CNAME 5					// CNAME record type
#define INTERNET_DATA 1			// Internet query class
#define MAX_SIZE 4096

static short conversationId = 0;
int setQueryMsg(char *domainName, char *buffer, int queryType, int queryClass);
int parseResponse();

// Main function
int main(int argc, char *argv[])
{
	// Try to query from DNS server set by /etc/resolv.conf
	// First Mannuly set server
	char queryMsg[MAX_SIZE];
	// Set header
	
	


	// Print parameters,including command name,splited by space
	if (argc != 0)
	{
		for	(int i = 0; i < argc; i++)
		{
			printf("%s\n", argv[i]);
		}
	}
	return 0;
}

int setQueryMsg(char *domainName, char *buffer, int queryType, int queryClass)
{
	if (domainName == NULL || buffer == NULL)
	{
		perror("NULL pointer");
		return -1;
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
	char *name = buffer + 12;
	char *counter = name;
	while (domainName[0] != '\0')
	{
		for (*counter = 0; domainName[cursor] != '.' && domainName[cursor] != '\0'; *counter++)
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
	return 0;
}


