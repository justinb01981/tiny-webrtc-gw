#ifndef __DEBUG_H__
#define __DEBUG_H__

#define HD(buf, len) {int hdx; for(hdx=0; hdx < len; hdx++) printf("%02x ", (unsigned char) buf[hdx]); printf("\n"); }

#define ADDR_TO_STRING(addr) (inet_ntoa((addr).sin_addr))
#define ADDR_PORT(addr) (ntohs((addr).sin_port))

#endif
