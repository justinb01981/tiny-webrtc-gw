#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "boolhack.h"

int stun_xor_addr(int sockfd,char * stun_server_ip,unsigned short stun_server_port,char * return_ip, unsigned short * return_port)
{
    struct sockaddr_in servaddr;

    unsigned char buf[300];
    int i;
    unsigned char bindingReq[20];    

    int stun_method,msg_length;\
    short attr_type;
    short attr_length;
    short port;
    short n;
    int response = FALSE;

    // server
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, stun_server_ip, &servaddr.sin_addr);
    servaddr.sin_port = htons(stun_server_port);   
    //## first bind 
         
    printf("stun_xor_addr:%d\n", __LINE__);

    int k;
    * (short *)(&bindingReq[0]) = htons(0x0001);    // stun_method
    * (short *)(&bindingReq[2]) = htons(0x0000);    // msg_length
    * (int *)(&bindingReq[4])   = htonl(0x2112A442);// magic cookie
    *(int *)(&bindingReq[8]) = htonl(0x63c7117e);   // transacation ID 
    *(int *)(&bindingReq[12])= htonl(0x0714278f);
    *(int *)(&bindingReq[16])= htonl(0x5ded3221);
    n = sendto(sockfd, bindingReq, sizeof(bindingReq),0,(struct sockaddr *)&servaddr, sizeof(servaddr));
    if (n == -1)
    {
        printf("sendto error\n");
        return -1;
    }

    // time wait 2 sec
    usleep(1000 * 2);

    n = recvfrom(sockfd, buf, 300, 0, NULL,0); // recv UDP
    if (n == -1)
    {
        printf("recvfrom error\n");
        return -2;
    }
    
    if (*(short *)(&buf[0]) == htons(0x0101))
    {
        printf("STUN binding resp: success !\n");
                                                                                                                                                                      
        n = htons(*(short *)(&buf[2]));
                                                                                                                                                                    
        i = 20;
                                                                                                                                                                                                                                                                                                        
        while(i<sizeof(buf))                                                                                                                                                                                                                                                                                                               
        {
            attr_type = htons(*(short *)(&buf[i]));
                                                                                                                                                                                                                                                                                                                                                            
            attr_length = htons(*(short *)(&buf[i+2]));
                                                                                                                                                                                                                                                                                                                                                                        
            if (attr_type == 0x0020)
            {
                response = TRUE;

                // parse : port, IP                                                                                                                                                                                                                                                                                                                                                                                                             
                port = ntohs(*(short*)(&buf[i + 6]));
                port ^= 0x2112;

                printf("@port = %d\n", (unsigned short)port);

                printf("@ip   = %d.",buf[i+8] ^ 0x21);
                printf("%d.",buf[i+9] ^ 0x12);
                printf("%d.",buf[i+10] ^ 0xA4);
                printf("%d\n",buf[i+11] ^ 0x42);

                *return_port = port;
                sprintf(return_ip, "%d.%d.%d.%d", buf[i + 8] ^ 0x21, buf[i + 9] ^ 0x12, buf[i + 10] ^ 0xA4, buf[i + 11] ^ 0x42);

                break;
            }
        }
        i += (4  + attr_length);
    }

    return response != TRUE;
}

unsigned char iplookup_addr[64] = {0};
unsigned short iplookup_portnum;

static const char *server = "74.125.250.129"; //"173.194.193.127";

const char* ip2LocationFetchIPV4Public(int sockfd)
{
    int n;

    do   {
        n = stun_xor_addr(sockfd, server, 19302, (char*) iplookup_addr, &iplookup_portnum);
    } while (n != 0);

    return (const char*) iplookup_addr;
}

const unsigned int ip2LocationFetchIPV4PublicPort(int sockfd)
{
    int n;
    do {
        n = stun_xor_addr(sockfd, server, 19302, (char*) iplookup_addr, &iplookup_portnum);
    } while (n != 0);

    return iplookup_portnum;
}
