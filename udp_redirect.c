/* http://www.brokestream.com/udp_redirect.html
 
  Build: gcc -o udp_redirect udp_redirect.c
 
  udp_redirect.c
  Version 2013-05-30
 
  Copyright (C) 2007 Ivan Tikhonov
  Copyright (C) 2013 Stuart Shelton, HP Autonomy
 
  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.
 
  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:
 
  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
 
  Ivan Tikhonov, kefeer@brokestream.com
 
  This source has been modified to support sending data to the destination
  IP address from a different source-ip to the listen-ip, to enable proxying
  on multi-homed hosts
 
  Stuart Shelton, stuart.shelton@hp.com
 
*/
 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
 
int bindsocket( char* ip, int port );
int main( int argc, char* argv[] );
 
int bindsocket( char* ip, int port ) {
    int fd;
    struct sockaddr_in addr;
 
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr( ip );
    addr.sin_port = htons( port );
 
    fd = socket( PF_INET, SOCK_DGRAM, IPPROTO_IP );
    if( -1 == bind( fd, (struct sockaddr*)&addr, sizeof( addr ) ) ) {
        fprintf( stderr, "Cannot bind address (%s:%d)\n", ip, port );
        exit( 1 );
    }
 
    return fd;
}

#define HD(buf, len) {int hdx; for(hdx=0; hdx < len; hdx++) printf("%02x ", (unsigned char) buf[hdx]); printf("\n"); }

typedef struct
{
    struct {
        char key[64];
    } crypto;
} peer_session_t;

typedef enum
{
    PKT_TYPE_STUN = 0,
    PKT_TYPE_DTLS,
    PKT_TYPE_SRTP,
    PKT_TYPE_UNKNOWN
} pkt_type_t;

pkt_type_t pktType(unsigned char* buf, unsigned int len)
{
    if(len >= 3 &&
       (buf[0] == 0x01 || buf[0] == 0x00) &&
       (buf[1] == 0x01 || buf[1] == 0x11) &&
       buf[2] == 0x00)
    {
        return PKT_TYPE_STUN;
    }

    if(len >= 2 &&
       (buf[0] == 90 && buf[1] == 0x6d))
    {
        /* TURN datachannel message */
        return PKT_TYPE_STUN;
    }

    if(len >= 3 &&
       (buf[0] == 0x14 || buf[0] == 0x16) &&
       (buf[1] == 0xfe) &&
       (buf[2] == 0xfd))
    {
        return PKT_TYPE_DTLS;
    }

    if(len >= 2 &&
       buf[0] == 0x80 || buf[0] == 0x90 || buf[0] == 0x81)
    {
        return PKT_TYPE_SRTP;
    }

    HD(buf, len);

    return PKT_TYPE_UNKNOWN;
}

unsigned int stunID(unsigned char* buf, unsigned int len)
{
    unsigned int l = 0;
    unsigned int offset = 32;

    if(pktType(buf, len) == PKT_TYPE_STUN && len >= offset + sizeof(l))
    {
        memcpy(&l, &(buf[offset]), sizeof(l));
    }
    return l;
}
 
int main( int argc, char* argv[] ) {
    int i, listen, output;
    char *inip, *inpt, *srcip, *dstip, *dstpt;
    struct sockaddr_in src;
    struct sockaddr_in dst;
    struct sockaddr_in ret;

    int bounce_mode = 0;
    unsigned int masterID = 0;
    char* counts_names[8] = {"in_STUN", "in_SRTP", "in_UNK", "DROP", "BYTES_FWD", "", "USER_ID", "master"};
    int counts[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    struct sockaddr_in saList[16];
    unsigned int saListID[16];
    unsigned int saListFwd[16];
    peer_session_t saListPeerData[16];
    int saListLen = 0;
    int saListMax = 0;

    memset(&saList, 0, sizeof(saList)); 

    if( 3 != argc && 5 != argc && 6 != argc ) {
        fprintf( stderr, "Usage: %s <listen-ip> <listen-port> [[source-ip] <destination-ip> <destination-port>]\n", argv[ 0 ] );
        exit( 1 );
    }
 
    i = 1;
    inip = argv[ i++ ];     /* 1 */
    inpt = argv[ i++ ];     /* 2 */
    if( 6 == argc )
        srcip = argv[ i++ ];    /* 3 */
    if( 3 != argc ) {
        dstip = argv[ i++ ];    /* 3 or 4 */
        dstpt = argv[ i++ ];    /* 4 or 5 */
    }

    if(strstr(argv[0], "bounce") != 0) bounce_mode = 1;
     
    listen = bindsocket( inip, atoi( inpt ) );
    if( 6 == argc ) {
        output = bindsocket( srcip, atoi( inpt ) );
    } else {
        output = listen;
    }
 
    if( 3 != argc ) {
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = inet_addr( dstip );
        dst.sin_port = htons( atoi( dstpt ) );
    }
    ret.sin_addr.s_addr = 0;

    while( 1 ) {
        char buffer[65535];
        unsigned int size = sizeof( src );
        int length = recvfrom( listen, buffer, sizeof( buffer ), 0, (struct sockaddr*)&src, &size );
        if( length <= 0 )
            continue;

        if( 3 == argc && !bounce_mode) {
            /* echo, without tracking return packets */
            sendto( listen, buffer, length, 0, (struct sockaddr*)&src, size );
        } else if(bounce_mode) {
            int inkey = 0;
            static unsigned long time_lastchar = 0;

            if(time(NULL) - time_lastchar > 1) {
                FILE* fp = fopen("masterid.txt", "r");
                if(fp) { fscanf(fp, "%d", &masterID); fclose(fp); }
                time_lastchar = time(NULL);
            }

            if(inkey == 'u') masterID++;
            else if(inkey == 'd') masterID--;

            pkt_type_t type = pktType(buffer, length);

            if(type == PKT_TYPE_STUN) counts[0]++;
            if(type == PKT_TYPE_SRTP) counts[1]++;
            else counts[2]++;

            int i;
            int sidx = -1;
            for(i = 0; i < 16; i++)
            {
                if((src.sin_addr.s_addr == saList[i].sin_addr.s_addr &&
                    src.sin_port == saList[i].sin_port) ||
                   saListID[i] == stunID(buffer, length))
                {
                    //printf("found stunID: %d\n", stunID(buffer, length));
                    sidx = i;
                    break;
                }
            }

            if(sidx == -1 && (saListMax == 0 || saListLen < saListMax))
            {
                sidx = saListLen;
                saListLen++;
                if(saListLen >= 16) saListLen = 0;
                saList[sidx] = src;
                saListID[sidx] = stunID(buffer, length);
                saListFwd[sidx] = 16;
                masterID = sidx;
                counts[6]++;
            }

            /* drop RTP packets not from master */
            if(type != PKT_TYPE_STUN &&
               sidx != masterID &&
               saListFwd[sidx] == 0) {
                sidx = -1;
                counts[3]++;
            }
            if(saListFwd[sidx] > 0) saListFwd[sidx]--;

            for(i = 0; i < 16 && sidx != -1; i++)
            {
                if(i != sidx /*&& saListID[sidx] != saListID[i]*/)
                {
                    int r = sendto( output, buffer, length, 0, (struct sockaddr*)&saList[i], sizeof( saList[i] ) );
                    //printf("bounced %d bytes to %s:%d\n", r, inet_ntoa(saList[i].sin_addr), ntohs(saList[i].sin_port));
                    if(r > 0) counts[4] += r;
                }
            }

            counts[7] = masterID;

            printf("\n");
            
            int c;
            for(c = 0; c < 8; c++) printf("%s:%d ", counts_names[c], counts[c]);
        } else if( ( src.sin_addr.s_addr == dst.sin_addr.s_addr ) && ( src.sin_port == dst.sin_port ) ) {
            /* If we receive a return packet back from our destination ... */
            if( ret.sin_addr.s_addr )
                /* ... and we've previously remembered having sent packets to this location,
                   then return them to the original sender */
                sendto( output, buffer, length, 0, (struct sockaddr*)&ret, sizeof( ret ) );
                printf("bridging UDP (len=%d)\n", length);
        } else {
            sendto( output, buffer, length, 0, (struct sockaddr*)&dst, sizeof( dst ) );
            /* Remeber original sender to direct return packets towards */
            ret = src;
            printf("received UDP (len=%d)\n", length);
        }
    }
}
