#ifndef _SOCKET_H_
#define _SOCKET_H_
#include <WinSock2.h>
#include <stdint.h>

enum v6_packet_header {
    PUNCH_PING,
    PUNCH_PONG,
    PUNCH_FROM_CLIENT,
    PUNCH_FROM_RELAY
};

EXTERN_C int isSocketMapped(SOCKET socket);
EXTERN_C void unmapSocket(SOCKET socket);
EXTERN_C void mapSocket(SOCKET socket, uint16_t hport);
EXTERN_C void startKeepAliveIfNotStarted();
EXTERN_C const struct sockaddr_in6 *lockAndReadRelaySockaddr();
EXTERN_C void unlockRelaySockaddr();
#endif