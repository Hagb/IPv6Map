#ifndef _SOCKET_H_
#define _SOCKET_H_
#include <WinSock2.h>
#include <in6addr.h>
#include <stdint.h>
#include <ws2def.h>
#include <ws2ipdef.h>

enum v6_packet_header {
	PUNCH_PING,
	PUNCH_PONG,
	PUNCH_FROM_CLIENT,
	PUNCH_FROM_RELAY,
#ifdef BUILD_FOR_SOKU
#if BUILD_FOR_SOKU
	V6_SOKU_HELLO,
	V6_SOKU_REDIRECT
#endif
#endif
};

#ifdef BUILD_FOR_SOKU
#if BUILD_FOR_SOKU
#pragma pack(push, 1)
struct punch_pingpong {
	char header6;
	char header;
};
struct punch_request {
	char header6;
	char header;
	char is_second;
	struct in6_addr sin6_addr;
	uint16_t sin6_port;
};
struct soku_hello {
	char header;
	struct sockaddr_in peer_address;
	struct sockaddr_in target_address;
	char stuff[4];
};
struct v6_soku_hello {
	char header6;
	char header;
	struct in6_addr peer_address6;
	uint16_t peer_port;
	struct in6_addr target_address6;
	uint16_t target_port;
	char stuff[4];
};
struct soku_redirect {
	char header;
	unsigned int child_id;
	struct sockaddr_in target_address;
	char stuff[48];
};
struct v6_soku_redirect {
	char header6;
	char header;
	unsigned int child_id;
	struct in6_addr target_address6;
	uint16_t target_port;
	char stuff[48];
};
#pragma pack(pop)
#endif
#endif

EXTERN_C int isSocketMapped(SOCKET socket);
EXTERN_C void unmapSocket(SOCKET socket);
EXTERN_C void mapSocket(SOCKET socket, uint16_t hport);
EXTERN_C void startKeepAliveIfNotStarted();
EXTERN_C const struct sockaddr_in6 *lockAndReadRelaySockaddr();
EXTERN_C void unlockRelaySockaddr();
#endif