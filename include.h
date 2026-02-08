#ifndef MAIN_INCLUDE
#define MAIN_INCLUDE
#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h>
#include <byteswap.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <time.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <ctype.h>

typedef u_int8_t   uint8;
typedef u_int16_t  uint16;
typedef u_int32_t  uint32;
typedef u_int64_t  uint64;
typedef int8_t     int8;
typedef int16_t    int16;
typedef int32_t    int32;
typedef int64_t    int64;
typedef int8       bool;

#define false 0
#define true 1

#define NEEDS_CONVERT /* needs to be converted to network byte order */

#define PACKED __attribute__((__packed__))

#define AS_TRANS 23456

#endif
