#ifndef _MY_SOCKET_H_
#define _MY_SOCKET_H_
#include <WinSock2.h>
#include "addr_map.h"

// EXTERN_C SOCKET WINAPI my_socket(int af_original, int type, int protocol);
EXTERN_C int WINAPI my_recvfrom(SOCKET s, char *out_buf, int len, int flags, struct sockaddr *from_original, int *fromlen_original);
EXTERN_C int WINAPI my_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to_original, int tolen_original);
EXTERN_C int WINAPI my_bind(SOCKET s, const struct sockaddr *name_original, int namelen_original);
EXTERN_C int WINAPI my_closesocket(SOCKET s);
EXTERN_C int WINAPI my_getsockopt(SOCKET s, int level, int optname, char *optval_original, int *optlen_original);
EXTERN_C int WINAPI my_getsockname(SOCKET s, struct sockaddr *name_original, int *namelen_original);
EXTERN_C int WINAPI my_getpeername(SOCKET s, struct sockaddr *name_original, int *namelen_original);
EXTERN_C SOCKET WINAPI my_socket(int af, int type, int protocol);

EXTERN_C int(WINAPI *actual_recvfrom)(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
EXTERN_C int(WINAPI *actual_sendto)(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
EXTERN_C int(WINAPI *actual_bind)(SOCKET s, const struct sockaddr *name, int namelen);
EXTERN_C int(WINAPI *actual_closesocket)(SOCKET s);
EXTERN_C int(WINAPI *actual_getsockopt)(SOCKET s, int level, int optname, char *optval, int *optlen);
EXTERN_C int(WINAPI *actual_getsockname)(SOCKET s, struct sockaddr *name, int *namelen);
EXTERN_C int(WINAPI *actual_getpeername)(SOCKET s, struct sockaddr *name, int *namelen);
EXTERN_C SOCKET(WINAPI *actual_socket)(int af, int type, int protocol);
#endif