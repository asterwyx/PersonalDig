#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>


#define DNS_SERVER 		"114.114.114.114"	// Local DNS server
#define SERV_PORT 		53				// Standard DNS query port
#define A 				1				// A record type
#define NS 				2				// NS record type
#define CNAME 			5				// CNAME record type
#define AAAA			28				// IPv6 address type
#define IN_DATA 		1				// Internet query class
#define MAX_SIZE 		2048
#define MAX_MALLOC_TRY 	3
#define OK				0
#define FAIL			-1
#define YES				1
#define NO				0
#define STD_QUERY  		0
#define MAX_ID			10000
#define MAX_LAYERS		20				// 允许查询主机域名的最大长度
#define DEBUG_BUF(a, b, c) \
printf("%s\n", c);\
for (int i = 0; i < b; i++)\
{\
	printf("%x ", a[i]);\
}\
printf("\n");

typedef unsigned char byte;
#pragma pack(1)
typedef struct dns_header {
	unsigned short conversation_id; // Conversation identifier
	unsigned short qr_flag:1;     	// Query or response flag, 0 for query, 1 for response
	unsigned short opcode_flag:4; 	// Operation code flag, 0 for standard query, 1 for reversal query, 2 for server status request
	unsigned short aa_flag:1;     	// Authoritive answer, only response will set this
	unsigned short tc_flag:1;     	// 1 for truncated, 0 for not
	unsigned short rd_flag:1;     	// Desire recursive query
	unsigned short ra_flag:1;     	// Whether recursive query is available
	unsigned short :3;
	unsigned short rcode_flag:4;  	// Return code, 0 for success, 3 for name error, 2 for server error
	unsigned short qd_count;		// Queries count
	unsigned short an_count;		// Answers count
	unsigned short ns_count;		// Number of name server resource records
	unsigned short ar_count;		// Number of resource records in the additional records section
} DNS_HEADER;
#pragma pack()

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
	DNS_HEADER *header;
	QUESTION *question_sec;
} QUERY;

typedef struct response {
	DNS_HEADER *header;
	QUESTION *question_sec;
	RES_RECORD *answer_sec;
	RES_RECORD *authority_sec;
	RES_RECORD *additional_sec;
} RESPONSE;

// Print option args

typedef struct print_option
{
	// TODO
	byte noall;			// Have no all below, just display answers
	byte nocomments;	// Have no prompt
	byte nostats;		// Have no stats
	byte noquestions;	// Have no question section
	byte noadditional;	// Have no additional section
} p_option_t;

typedef struct args_pack
{
	int queryType;								// 查询种类，A或者NS或者CNAME
	int queryClass;								// 查询类别，IN或者CH或者其他
	int operationCode;							// 查询操作，标准查询等
	int truncated;								// 是否可截断
	int recursionDesirable;						// 是否期待递归查询
	int isReversal;								// 是否反解析
	unsigned char queryDomainName[MAX_SIZE];	// 查询的域名
	unsigned char queryMsg[MAX_SIZE];			// 查询DNS报文
	unsigned char responseMsg[MAX_SIZE];		// 响应DNS报文
	int queryLen;								// 查询的报文长度
	int responseLen;							// 响应的报文长度
	char serverAddr[MAX_SIZE];					// 使用的DNS服务器，默认是读取/etc/resolv.conf中的内容，选取第一个
	unsigned short serverPort;					// 使用的查询端口，默认为53
	byte trace_on;								// 是否开启追踪模式
} args_pack_t;

static short conversationId = 0;
void setQueryQuestion(unsigned char *domainName, QUESTION *question, int queryType, int queryClass);
int printQueryToBuf(QUERY *query, unsigned char *buffer, int *bufferSize, int isReversal);
int setQueryMsg(char *domainName, unsigned char *buffer, int queryType, int queryClass);												// Set query struct
RESPONSE* parseResponse(unsigned char *response, int responseLen, int queryLen);														// Parse DNS response
unsigned char *changeNetStrToNormal(unsigned char *netStr, int *netStrLem, int *normalStrLen, int netStrType, unsigned char *context);	// Change net form to normal
unsigned char *changeNormalStrToNet(unsigned char *normalStr, int *normalStrLen, int *netStrLen, int netStrType);						// Change normal form to net
int printResult(RESPONSE *response, p_option_t *print_options);																			// Print result
void setQueryHeader(DNS_HEADER *header, int operation_code, int truncated, int recursionDesirable);										// Set header by arg
void setArgs(int argc, char *argv[], args_pack_t *args);
void initArgs(args_pack_t *args);
void sendQuery(QUERY *query, RESPONSE **response, args_pack_t *args);
unsigned char** splitDomainNameToLayers(char *domainName, int *layerNum);


// Main function
int main(int argc, char *argv[])
{
	args_pack_t *queryArgs = (args_pack_t *)malloc(sizeof(args_pack_t));
	initArgs(queryArgs);
	if (argc > 1)
	{
		strcpy((char *)queryArgs->queryDomainName, argv[argc - 1]);
	}
	// Try to query from DNS server set by /etc/resolv.conf
	// First Mannuly set server
	
	QUERY *query = (QUERY *)malloc(sizeof(QUERY));
	if (query == NULL)
	{
		perror("Out of space!");
		return 0;
	}
	query->header = (DNS_HEADER *)malloc(sizeof(DNS_HEADER));
	query->question_sec = (QUESTION *)malloc(sizeof(QUESTION));
	setQueryHeader(query->header, queryArgs->operationCode, queryArgs->truncated, queryArgs->recursionDesirable);
	setQueryQuestion(queryArgs->queryDomainName, query->question_sec, queryArgs->queryType, queryArgs->queryClass);
	RESPONSE* response = NULL;	
	if (queryArgs->trace_on == NO)
	{
		sendQuery(query, &response, queryArgs);
		printResult(response, NULL);	
	}
	else
	{
		queryArgs->recursionDesirable = NO;
		setQueryHeader(query->header, queryArgs->operationCode, queryArgs->truncated, queryArgs->recursionDesirable);
		char fullDomainName[MAX_SIZE] = {0};
		strcpy(fullDomainName, (char *)queryArgs->queryDomainName);
		int layerNum = 0;
		unsigned char **layers = splitDomainNameToLayers(fullDomainName, &layerNum);
		for (int i = 0; i < layerNum - 1; i++)
		{
			// 查询各级域名的权威服务器
			setQueryQuestion(layers[i], query->question_sec, NS, query->question_sec->qclass);
			sendQuery(query, &response, queryArgs);
			p_option_t* options;
			options->noadditional = YES;
			options->nocomments = YES;
			options->noquestions = YES;
			options->nostats = YES;
			options->noall = NO;
			printResult(response, NULL);
			setQueryQuestion(response->answer_sec->data, query->question_sec, A, query->question_sec->qclass);
			sendQuery(query, &response, queryArgs);
			printResult(response, NULL);
			for (int i = 0; i < response->header->an_count; i++)
			{
				if (response->answer_sec[i].type == A)
				{
					strcpy(queryArgs->serverAddr, (char *)response->answer_sec[i].data);
					break;
				}
			}
		}
		// 向最新获得的域名DNS服务器发送查询
		setQueryQuestion(layers[layerNum - 1], query->question_sec, queryArgs->queryType, query->question_sec->qclass);
		sendQuery(query, &response, queryArgs);
		printResult(response, NULL);
	}
	
	return 0;
}

void setQueryQuestion(unsigned char *domainName, QUESTION *question, int queryType, int queryClass)
{
	question->domainName = (unsigned char *)malloc(MAX_SIZE);
	strcpy((char *)question->domainName, (char *)domainName);
	question->qtype = (unsigned short)queryType;
	question->qclass = (unsigned short)queryClass;
}

int printQueryToBuf(QUERY *query, unsigned char *buffer, int *bufferSize, int isReversal)
{
	if (query == NULL)
	{
		perror("NULL pinter!");
		return FAIL;
	}
	else
	{
		if (query->header == NULL || query->question_sec == NULL)
		{
			perror("NULL pinter!");
			return FAIL;
		}
		else
		{
			unsigned short *tmp = (unsigned short *)buffer;
			*tmp = htons(query->header->conversation_id);
			tmp++;
			buffer[2] = 0x00 | (query->header->qr_flag << 7) | (query->header->opcode_flag << 3) | (query->header->aa_flag << 2) | (query->header->tc_flag << 1) | (query->header->rd_flag);
			buffer[3] = 0x00 | (query->header->ra_flag << 7) | (query->header->rcode_flag);
			tmp++;
			*tmp = htons(query->header->qd_count);
			tmp++;
			*tmp = htons(query->header->an_count);
			tmp++;
			*tmp = htons(query->header->ns_count);
			tmp++;
			*tmp = htons(query->header->ar_count);	//　拷贝header到缓冲区
			int netStrLen = 0;
			unsigned char *netStr = NULL;
			if (query->question_sec->domainName == NULL)
			{
				perror("NULL pinter!");
				return FAIL;
			}
			else
			{
				if (isReversal == NO)
				{
					netStr = changeNormalStrToNet(query->question_sec->domainName, NULL, &netStrLen, CNAME);
				}
				else
				{
					netStr = changeNormalStrToNet(query->question_sec->domainName, NULL, &netStrLen, A);
				}
			}
			// printf("Net str length: %d\n", netStrLen);
			memcpy(buffer + 12, netStr, netStrLen);
			tmp = (unsigned short *)(buffer + 12 + netStrLen);
			*tmp = htons(query->question_sec->qtype);
			tmp++;
			*tmp = htons(query->question_sec->qclass);
			*bufferSize = (unsigned char *)tmp - buffer + 2;
			// printf("Buffer size: %d\n", *bufferSize);
			return OK;
		}	
	}
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


RESPONSE* parseResponse(unsigned char *response, int responseLen, int queryLen)
{
	unsigned short *cursor;
	RESPONSE *result = (RESPONSE *)malloc(sizeof(RESPONSE));
	memset(result, 0, sizeof(RESPONSE));
	result->header = (DNS_HEADER *)malloc(sizeof(DNS_HEADER));
	memset(result->header, 0, sizeof(DNS_HEADER));
	result->question_sec = (QUESTION *)malloc(sizeof(QUESTION));
	memset(result->question_sec, 0, sizeof(QUESTION));
	cursor = (unsigned short *)response;
	result->header->conversation_id = ntohs(*cursor);   // Change net order to host order
	// Set flag
	cursor++;
	result->header->qr_flag = ((*cursor) >> 7) & 0x0001;
	result->header->opcode_flag = ((*cursor) >> 3) & 0x000f;
	result->header->aa_flag = ((*cursor) >> 2) & 0x0001;
	result->header->tc_flag = ((*cursor) >> 1) & 0x0001;
	result->header->rd_flag = (*cursor) & 0x0001;
	result->header->ra_flag = ((*cursor) >> 15) & 0x0001;
	result->header->rcode_flag = ((*cursor) >> 8) & 0x000f;
	// Set query count
	cursor++;
	result->header->qd_count = ntohs(*cursor);
	// Set answer count
	cursor++;
	result->header->an_count = ntohs(*cursor);
	// Set name server count
	cursor++;
	result->header->ns_count = ntohs(*cursor);
	// Set additional records count
	cursor++;
	result->header->ar_count = ntohs(*cursor);
	// Set question_sec and resource_records sec
	int nameLen, netStrLen;
	result->question_sec->domainName = changeNetStrToNormal(response + 12, &netStrLen, &nameLen, CNAME, response);
	result->question_sec->qtype = ntohs(*(unsigned short *)(response + queryLen - 4));
	result->question_sec->qclass = ntohs(*(unsigned short *)(response + queryLen - 2));
	
	int counter = 0;
	do
	{
		result->answer_sec = (RES_RECORD *)malloc(sizeof(RES_RECORD) * result->header->an_count);	
		counter++;
	} while(result->answer_sec == NULL && counter < MAX_MALLOC_TRY);
	counter = 0;
	do
	{
		result->authority_sec = (RES_RECORD *)malloc(sizeof(RES_RECORD) * result->header->ns_count);
		counter++;
	} while(result->authority_sec == NULL && counter < MAX_MALLOC_TRY);
	counter = 0;
	do
	{
		result->additional_sec = (RES_RECORD *)malloc(sizeof(RES_RECORD) * result->header->ar_count);
		counter++;	
	} while(result->additional_sec == NULL && counter < MAX_MALLOC_TRY);
	if (result->answer_sec == NULL || result->authority_sec == NULL || result->additional_sec == NULL)
	{
		perror("Malloc failed, out of space!!!");
		free(result);
		return NULL;
	}
	// Start parse answers and RRs
	int readPos = queryLen;
	for (int i = 0; i < result->header->an_count; i++)
	{
		unsigned short *readPtr = (unsigned short *)(response + readPos);
		int posOffset = 0;
		int normalStrLen = 0;
		if ((ntohs(*readPtr) >> 14) == 0x0003)
		{
			result->answer_sec[i].name = changeNetStrToNormal(response + (ntohs(*readPtr) & 0x3fff), &posOffset, &normalStrLen, CNAME, response);
			readPos += 2;
		}
		else
		{
			result->answer_sec[i].name = changeNetStrToNormal(response + readPos, &posOffset, &normalStrLen, CNAME, response);
			readPos += posOffset;
		}
		readPtr = (unsigned short *)(response + readPos);
		result->answer_sec[i].type = ntohs(*readPtr);
		readPtr++;
		result->answer_sec[i]._class = ntohs(*readPtr);
		readPtr++;
		result->answer_sec[i].ttl = ntohl(*(unsigned int *)readPtr);
		readPtr += 2;
		result->answer_sec[i].data_length = ntohs(*readPtr);
		readPos += 10;
		result->answer_sec[i].data = changeNetStrToNormal(response + readPos, &posOffset, &normalStrLen, result->answer_sec[i].type, response);
		readPos += posOffset;
	}

	for (int i = 0; i < result->header->ns_count; i++)
	{
		unsigned short *readPtr = (unsigned short *)(response + readPos);
		int posOffset = 0;
		int normalStrLen = 0;
		if ((ntohs(*readPtr) >> 14) == 0x0003)
		{
			result->authority_sec[i].name = changeNetStrToNormal(response + (ntohs(*readPtr) & 0x3fff), &posOffset, &normalStrLen, CNAME, response);
			readPos += 2;
		}
		else
		{
			result->authority_sec[i].name = changeNetStrToNormal(response + readPos, &posOffset, &normalStrLen, CNAME, response);
			readPos += posOffset;
		}
		readPtr = (unsigned short *)(response + readPos);
		result->authority_sec[i].type = ntohs(*readPtr);
		readPtr++;
		result->authority_sec[i]._class = ntohs(*readPtr);
		readPtr++;
		result->authority_sec[i].ttl = ntohl(*(unsigned int *)readPtr);
		readPtr += 2;
		result->authority_sec[i].data_length = ntohs(*readPtr);
		readPos += 10;
		result->authority_sec[i].data = changeNetStrToNormal(response + readPos, &posOffset, &normalStrLen, result->authority_sec[i].type, response);
		readPos += posOffset;
	}

	for (int i = 0; i < result->header->ar_count; i++)
	{
		unsigned short *readPtr = (unsigned short *)(response + readPos);
		int posOffset = 0;
		int normalStrLen = 0;
		if ((ntohs(*readPtr) >> 14) == 0x0003)
		{
			result->additional_sec[i].name = changeNetStrToNormal(response + (ntohs(*readPtr) & 0x3fff), &posOffset, &normalStrLen, CNAME, response);
			readPos += 2;
		}
		else
		{
			result->additional_sec[i].name = changeNetStrToNormal(response + readPos, &posOffset, &normalStrLen, CNAME, response);
			readPos += posOffset;
		}
		readPtr = (unsigned short *)(response + readPos);
		result->additional_sec[i].type = ntohs(*readPtr);
		readPtr++;
		result->additional_sec[i]._class = ntohs(*readPtr);
		readPtr++;
		result->additional_sec[i].ttl = ntohl(*(unsigned int *)readPtr);
		readPtr += 2;
		result->additional_sec[i].data_length = ntohs(*readPtr);
		readPos += 10;
		result->additional_sec[i].data = changeNetStrToNormal(response + readPos, &posOffset, &normalStrLen, result->additional_sec[i].type, response);
		readPos += posOffset;
	}
	return result;
}

unsigned char *changeNetStrToNormal(unsigned char *netStr, int *netStrLen, int *normalStrLen, int netStrType, unsigned char *context)
{
	*netStrLen = 0;
	*normalStrLen = 0;
	char *buffer = (char *)malloc(MAX_SIZE);
	int cursor = 0;
	switch (netStrType)
	{
		case A:
			*netStrLen = 4;
			sprintf(buffer, "%u.%u.%u.%u", netStr[0], netStr[1], netStr[2], netStr[3]);
			*normalStrLen = strlen(buffer);
			break;
		case NS:
		case CNAME:
			if (netStr[0] == '\0')
			{
				buffer[(*normalStrLen)++] = '.';
				buffer[*normalStrLen] = '\0';
				(*netStrLen) = 1;
			}
			else
			{
				while (1)
				{
					if (netStr[cursor] == 0)
					{
						(*netStrLen)++;
						buffer[*normalStrLen] = '\0';
						break;
					}
					else if ((netStr[cursor] >> 6) & 0x03 == 0x03)
					{
						(*netStrLen) += 2;
						int addStrLen = 0, addNetLen = 0;
						unsigned char *addStr = changeNetStrToNormal(context + (ntohs(*(unsigned short *)(netStr + cursor)) & 0x3fff), &addNetLen, &addStrLen, CNAME, context);
						strcpy(buffer + *normalStrLen, (char *)addStr);
						*normalStrLen += addStrLen;
						break;
					}
					else
					{
						for	(int i = 1; i <= netStr[cursor]; i++)
						{
							buffer[(*normalStrLen)++] = netStr[cursor + i];
						}
						buffer[(*normalStrLen)++] = '.';
						*netStrLen += netStr[cursor] + 1;
						cursor += netStr[cursor] + 1;
					}
				}	
			}
			break;
		default:
			break;
	}
	char *result = (char *)malloc(*normalStrLen + 1);
	strcpy(result, buffer);
	free(buffer);
	return (unsigned char *)result;
}

unsigned char *changeNormalStrToNet(unsigned char *normalStr, int *normalStrLen, int *netStrLen, int netStrType)
{
	unsigned char *result = (unsigned char *)malloc(MAX_SIZE);
	memset(result, 0, MAX_SIZE);
	int cursor = 0;
	unsigned char *counter = result;
	switch (netStrType)
	{
	case CNAME:
		while (normalStr[0] != '\0' && normalStr[0] != '.')
		{
			for (*counter = 0; normalStr[cursor] != '.' && normalStr[cursor] != '\0'; (*counter)++)
			{
				result[cursor + 1] = normalStr[cursor];
				cursor++;
			}
			// Set counter
			counter = result + 1 + cursor;
			if (normalStr[cursor] == '\0')
			{
				cursor++;
				break;
			}
			else if (normalStr[cursor] == '.' && normalStr[cursor + 1] == '\0')
			{
				cursor++;
				break;
			}
			else
			{
				cursor++;
			}
		}
		result[cursor++] = 0;			// Set end of buffer	
		break;
	case A:
		break;
	default:
		break;
	}
	if (netStrLen != NULL)
	{
		*netStrLen = cursor;
	}
	if (normalStrLen != NULL)
	{
		*normalStrLen = strlen((char *)normalStr);
	}
	return result;
}

int printResult(RESPONSE *response, p_option_t *print_options)
{
	printf("----------start----------");
	printf("\nHeader section:\n\n");
	printf("Conversation id: %d\n" 
		"Query or response flag: %d\n"
		"Operation code flag: %d\n"
		"Authoritive answer flag: %d\n"
		"Truncated flag: %d\n"
		"Recursion desired flag: %d\n"
		"Resursion available flag: %d\n"
		"Return code flag: %d\n"
		"Queries count: %d\n"
		"Answers count: %d\n"
		"Name servers count: %d\n"
		"Additional records count: %d\n"
		, response->header->conversation_id
		, response->header->qr_flag
		, response->header->opcode_flag
		, response->header->aa_flag
		, response->header->tc_flag
		, response->header->rd_flag
		, response->header->ra_flag
		, response->header->rcode_flag
		, response->header->qd_count
		, response->header->an_count
		, response->header->ns_count
		, response->header->ar_count);
	printf("\nQuestion section:\n\n");
	printf("DomainName               QueryType    QueryClass\n");
	printf("%-25s%-13u%-u\n", response->question_sec->domainName, response->question_sec->qtype, response->question_sec->qclass);
	
	printf("\nAnswer section\n\n");
	printf("Name                     TTL     Type     Class    Data\n");
	for (int i = 0; i < response->header->an_count; i++)
	{
		printf("%-25s%-8u%-9u%-9u%-s\n"
			, response->answer_sec[i].name
			, response->answer_sec[i].ttl
			, response->answer_sec[i].type
			, response->answer_sec[i]._class
			, response->answer_sec[i].data);
	}

	printf("\nName server section\n\n");
	printf("Name                     TTL     Type     Class    Data\n");
	for (int i = 0; i < response->header->ns_count; i++)
	{	
		printf("%-25s%-8u%-9u%-9u%-s\n"
			, response->authority_sec[i].name
			, response->authority_sec[i].ttl
			, response->authority_sec[i].type
			, response->authority_sec[i]._class
			, response->authority_sec[i].data);
	}

	printf("\nAdditional section\n\n");
	printf("Name                     TTL     Type     Class    Data\n");
	for (int i = 0; i < response->header->ar_count; i++)
	{
		printf("%-25s%-8u%-9u%-9u%-s\n"
			, response->additional_sec[i].name
			, response->additional_sec[i].ttl
			, response->additional_sec[i].type
			, response->additional_sec[i]._class
			, response->additional_sec[i].data);
	}
	printf("-----------end-----------\n");
	return 0;
}

void setQueryHeader(DNS_HEADER *header, int operation_code, int truncated, int recursionDesirable)
{
	srand(time(NULL));		// 设置随机种子
	header->conversation_id = rand() % MAX_ID;
	header->qr_flag = 0;
	header->opcode_flag = operation_code;
	header->aa_flag = 0;
	header->tc_flag = truncated;
	header->rd_flag = recursionDesirable;
	header->ra_flag = 0;
	header->rcode_flag = 0;
	header->qd_count = 1;
	header->an_count = 0;
	header->ns_count = 0;
	header->ar_count = 0;
}

void setArgs(int argc, char *argv[], args_pack_t *args)
{

}

void initArgs(args_pack_t *args)
{
	// 查询参数默认值
	args->queryType = A;
	args->queryClass = IN_DATA;
	args->operationCode = STD_QUERY;
	args->truncated = NO;
	args->recursionDesirable = YES;
	args->isReversal = NO;
	strcpy((char *)args->queryDomainName, ".");
	memset(args->queryMsg, 0, MAX_SIZE);
	memset(args->responseMsg, 0, MAX_SIZE);
	args->queryLen = 0;
	args->responseLen = 0;
	strcpy(args->serverAddr, DNS_SERVER);
	args->serverPort = SERV_PORT;
	args->trace_on = YES;
}

void sendQuery(QUERY *query, RESPONSE **response, args_pack_t *args)
{
	struct sockaddr_in dest_addr;
	memset(&dest_addr, 0, sizeof(struct sockaddr_in));
	dest_addr.sin_addr.s_addr = inet_addr(args->serverAddr);
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(args->serverPort);
	printQueryToBuf(query, args->queryMsg, &args->queryLen, args->isReversal);
	// debug macro
	DEBUG_BUF(args->queryMsg, args->queryLen, "Query message:");
	int sendSock = socket(PF_INET, SOCK_DGRAM, 0);
	int sentSize = sendto(sendSock, args->queryMsg, args->queryLen, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
	if (sentSize > 0)
	{
		printf("Successfully send queries!\n");
		printf("Sent size: %d\n", sentSize);
	}
	else
	{
		printf("Failed!\n");
	}
	args->responseLen = recv(sendSock, args->responseMsg, MAX_SIZE, 0);
	
	// Close socket
	close(sendSock);

	printf("Received size: %d\n", args->responseLen);	
	// For debugging, print reponse
	
	for (int i = 0; i < args->responseLen; i++)
	{
		printf("%x ", args->responseMsg[i]);
	}

	printf("\n\n\n");
	*response = parseResponse(args->responseMsg, args->responseLen, args->queryLen);
}

unsigned char** splitDomainNameToLayers(char *domainName, int *layerNum)
{
	unsigned char **layers;
	layers = (unsigned char **)malloc(sizeof(unsigned char *) * MAX_LAYERS);
	for (int i = 0; i < MAX_LAYERS; i++)
	{
		layers[i] = (unsigned char *)malloc(MAX_SIZE);
	}
	int nameLen = strlen(domainName);
	int j = 0;
	strcpy((char *)layers[j++], ".");
	for (int i = nameLen; i >= 0; i--)
	{
		if (domainName[i] == '.')
		{
			strcpy((char *)layers[j++], domainName + i + 1);
		}
	}
	*layerNum = j;
	return layers;
}