#ifndef _SOCKET_H_
#define _SOCKET_H_
#include <WinSock2.h>

EXTERN_C int isSocketMapped(SOCKET socket);
EXTERN_C void unmapSocket(SOCKET socket);
EXTERN_C void mapSocket(SOCKET socket);
#endif