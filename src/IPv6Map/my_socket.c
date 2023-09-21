#include "my_socket.h"

#include "addr_map.h"
#include "debug.h"
#include "socket_manage.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <winnt.h>

// TODO: my_connect, actual_connect
int(WINAPI *actual_recvfrom)(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) = recvfrom;
int(WINAPI *actual_sendto)(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) = sendto;
int(WINAPI *actual_bind)(SOCKET s, const struct sockaddr *name, int namelen) = bind;
int(WINAPI *actual_closesocket)(SOCKET s) = closesocket;
int(WINAPI *actual_getsockopt)(SOCKET s, int level, int optname, char *optval, int *optlen) = getsockopt;
int(WINAPI *actual_getsockname)(SOCKET s, struct sockaddr *name, int *namelen) = getsockname;
int(WINAPI *actual_getpeername)(SOCKET s, struct sockaddr *name, int *namelen) = getpeername;
SOCKET(WINAPI *actual_socket)(int af, int type, int protocol) = socket;

void debug_packet_information(const char *buf, int size) {
#ifdef BUILD_FOR_SOKU
#if BUILD_FOR_SOKU
	if (size >= 1)
		switch (*buf) {
		case 0x1:
			DEBUG_LOG("HELLO");
			break;
		case 0x3:
			DEBUG_LOG("OLLEH");
			break;
		case 0x2:
			DEBUG_LOG("PUNCH");
			break;
		case 0x5:
			DEBUG_LOG("INIT_REQUEST");
			break;
		case 0x6:
			DEBUG_LOG("INIT_SUCCESS");
			break;
		case 0x7:
			if (size >= 5)
				DEBUG_LOG("INIT_ERROR %d", *(int *)(buf + 1));
			break;
		case 0x8:
			DEBUG_LOG("REDIRECT");
			break;
		case 0xB:
			DEBUG_LOG("QUIT");
			break;
		}
#endif
#endif
}

inline bool check_sockaddr_in_and_set_error(const struct sockaddr *name, int namelen) {
	if (namelen >= sizeof(struct sockaddr_in) && name != NULL && name->sa_family == AF_INET) {
		return true;
	}
	DEBUG_LOG("error sockaddr_in, namelen=%d, nameptr%c=NULL, sa_family=%hu", namelen, name ? '!' : '=', name ? name->sa_family : 0);
	WSASetLastError(WSAEFAULT);
	return false;
}

SOCKET WINAPI my_socket(int af_original, int type, int protocol) {
	if (!(af_original == AF_INET && type == SOCK_DGRAM && (!protocol || protocol == IPPROTO_UDP))) {
		return actual_socket(af_original, type, protocol);
	}

#ifdef BUILD_FOR_SOKU
#if BUILD_FOR_SOKU
	void *traces[64] = {0};
	int traces_count = CaptureStackBackTrace(0, 63, traces, NULL);
	bool called_by_soku_itself = false;
	for (int i = 0; i < traces_count; i++) {
		DEBUG_LOG("trace: %p", traces[i]);
		if (traces[i] == (void *)0x00413123 || traces[i] == (void *)0x00446ac4 || traces[i] == (void *)0x00446bb1 || traces[i] == (void *)0x00446bf9) {
			called_by_soku_itself = true;
#if !DEBUG
			break;
#endif
		}
	}
	if (!called_by_soku_itself) {
		// a workaround. because hooks of WSA* functions hasn't been implemented
		// here.
		return actual_socket(af_original, type, protocol);
	}
#endif
#endif
	DEBUG_LOG("");
	SOCKET ret = actual_socket(AF_INET6, type, protocol);
	if (ret == INVALID_SOCKET) {
		// if there is error
		int error = WSAGetLastError();
		return actual_socket(af_original, type, protocol);
	}
	int disable = 0;
	if (setsockopt(ret, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&disable, sizeof(disable))) {
		int error = WSAGetLastError();
		DEBUG_LOG("failed to disable ipv6 only: %d , fallback to ipv4", error);
		if (actual_closesocket(ret)) {
			WSAGetLastError(); // ignore
		}
		return actual_socket(af_original, type, protocol);
	}
	mapSocket(ret, 0);
	return ret;
}

int WINAPI my_bind(SOCKET s, const struct sockaddr *name_original, int namelen_original) {
	if (!isSocketMapped(s))
		return actual_bind(s, name_original, namelen_original);
	DEBUG_LOG("");
	if (!check_sockaddr_in_and_set_error(name_original, namelen_original))
		return SOCKET_ERROR;

	struct sockaddr_in6 name6;
	if (sockaddr4to6((struct sockaddr_in *)name_original, &name6)) {
		WSASetLastError(WSAEADDRNOTAVAIL);
		return SOCKET_ERROR;
	}
	int ret = actual_bind(s, (struct sockaddr *)&name6, sizeof(name6));
#if DEBUG
	if (ret) {
		wchar_t v4[INET_ADDRSTRLEN];
		wchar_t v6[INET6_ADDRSTRLEN];
		addrtowstr((const struct sockaddr_in *)name_original, v4);
		addrtowstr(&name6, v6);
		int error = WSAGetLastError();
		DEBUG_LOG("error when bind: %d, %d. v4 addr: %ls ,v6 addr: %ls", ret, error, v4, v6);
		WSASetLastError(error);
	}
#endif
	int size = sizeof(name6);
	actual_getsockname(s, (struct sockaddr *)&name6, &size);
	mapSocket(s, ntohs(name6.sin6_port));
	DEBUG_LOG("bind [::]:%d", (int)ntohs(name6.sin6_port));
	startKeepAliveIfNotStarted();
	return ret;
}

int WINAPI my_recvfrom(SOCKET s, char *out_buf, int len, int flags, struct sockaddr *from_original, int *fromlen_original) {
	if (!isSocketMapped(s))
		return actual_recvfrom(s, out_buf, len, flags, from_original, fromlen_original);
	if (fromlen_original != NULL && *fromlen_original < sizeof(struct sockaddr_in)) {
		WSASetLastError(WSAEFAULT);
		DEBUG_LOG("from_original error");
		return SOCKET_ERROR;
	}
	struct sockaddr_in6 from;
	int fromlen = sizeof(struct sockaddr_in6);
	int ret = actual_recvfrom(s, out_buf, len, flags, (struct sockaddr *)&from, &fromlen);
	if (ret == SOCKET_ERROR) {
#if DEBUG
		int error = WSAGetLastError();
		DEBUG_LOG("error when recvfrom: %d", error);
		WSASetLastError(error);
#endif
		return ret;
	}
	debug_packet_information(out_buf, len);
	// DEBUG_LOG("recv %d", ret);
	sockaddr6to4(&from, (struct sockaddr_in *)from_original);
	if (fromlen_original != NULL)
		*fromlen_original = sizeof(struct sockaddr_in);
	if (ret >= 2 && out_buf[0] == '6') {
		switch (out_buf[1]) {
		case PUNCH_PING:
			DEBUG_LOG("get ping!"); // client doesn't reply ping
			// char data[] = {'6', PUNCH_PONG};
			// if (actual_sendto(s, data, sizeof(data), 0, (const struct sockaddr *)&from, sizeof(from)) == SOCKET_ERROR) {
			// 	int error = WSAGetLastError();
			// 	DEBUG_LOG("send pong response failed: %d", error);
			// }
			break;
		case PUNCH_PONG:
			DEBUG_LOG("get pong!");
			break;
		case PUNCH_FROM_RELAY:
			const struct sockaddr_in6 *relay_addr = lockAndReadRelaySockaddr();
			if (memcmp(&from.sin6_addr, &relay_addr->sin6_addr, sizeof(from.sin6_addr)) != 0) {
				unlockRelaySockaddr();
#if DEBUG
				wchar_t srcip[INET6_ADDRSTRLEN];
				wchar_t relayip[INET6_ADDRSTRLEN];
				addrtowstr((const struct sockaddr_in6 *)&from, srcip);
				addrtowstr(relay_addr, relayip);
				DEBUG_LOG("get PUNCH_FROM_RELAY, but src ip (%ls) is not the relay ip (%ls)", srcip, relayip);
#endif
				break;
			}
			unlockRelaySockaddr();
			uint16_t port = 0;
			if (ret < 3 + 16 + 2 || 0 == (port = *(uint16_t *)(out_buf + 3 + 16)))
				break;
			struct sockaddr_in6 sockaddr = {AF_INET6, port, 0, *(struct in6_addr *)(out_buf + 3), 0};
			{
				char data[] = {'6', PUNCH_PING};
				DEBUG_LOG("send ping for punch");
				if (actual_sendto(s, data, sizeof(data), 0, (const struct sockaddr *)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR) {
					int error = WSAGetLastError();
					DEBUG_LOG("fail to send ping for punch: %d", error);
				}
			}
			if (!out_buf[2]) {
				char data[3 + 16 + 2] = {'6', PUNCH_FROM_CLIENT, 1};
				memcpy(data + 3, &sockaddr.sin6_addr, 16);
				memcpy(data + 3 + 16, &sockaddr.sin6_port, 2);
				DEBUG_LOG("send punch request (1) to relay");
				const struct sockaddr_in6 *relay_addr = lockAndReadRelaySockaddr();
				if (actual_sendto(s, data, sizeof(data), 0, (const struct sockaddr *)relay_addr, sizeof(*relay_addr)) == SOCKET_ERROR) {
					int error = WSAGetLastError();
					DEBUG_LOG("fail to send punch request: %d", error);
				}
				unlockRelaySockaddr();
			}
			break;
		case PUNCH_FROM_CLIENT:
			DEBUG_LOG("unexpected punch packet from client! it should be sent to relay.");
			break;
		default:
			DEBUG_LOG("unknown v6 relay packet %d", out_buf[1]);
			break;
		}
	}
	return ret;
}

int WINAPI my_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to_original, int tolen_original) {
	if (!isSocketMapped(s))
		return actual_sendto(s, buf, len, flags, to_original, tolen_original);
	debug_packet_information(buf, len);
	// DEBUG_LOG("");
	if (!check_sockaddr_in_and_set_error(to_original, tolen_original))
		return SOCKET_ERROR;
	int tolen = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 to;
	if (sockaddr4to6((struct sockaddr_in *)to_original, &to)) {
		WSASetLastError(WSAEHOSTUNREACH);
		return SOCKET_ERROR;
	}
	int ret = actual_sendto(s, buf, len, flags, (struct sockaddr *)&to, tolen);
#if DEBUG
	if (ret == SOCKET_ERROR) {
		int error = WSAGetLastError();
		DEBUG_LOG("error when recvfrom: %d", error);
		WSASetLastError(error);
	} else {
		// DEBUG_LOG("send %d", ret);
	}
#endif
#ifdef BUILD_FOR_SOKU
#if BUILD_FOR_SOKU
	if (ret != SOCKET_ERROR && len >= 37 && buf[0] == 0x1 && buf[1] == 0x2 && buf[2] == 0x0) {
		// compare sin_family (2 bytes), sin_port (2 bytes) and sin_addr (4 bytes):
		if (*(uint64_t *)(buf + 1) != *(uint64_t *)(buf + 1 + 16))
			return ret;
		DEBUG_LOG("send punch request (0) to relay");
		char punch_request[3 + 16 + 2] = {'6', PUNCH_FROM_CLIENT, 0};
		memcpy(punch_request + 3, &to.sin6_addr, 16);
		memcpy(punch_request + 3 + 16, &to.sin6_port, 2);
		const struct sockaddr_in6 *relay_addr = lockAndReadRelaySockaddr();
		if (actual_sendto(s, punch_request, sizeof(punch_request), 0, (const struct sockaddr *)relay_addr, sizeof(*relay_addr)) == SOCKET_ERROR) {
			int error = WSAGetLastError();
			DEBUG_LOG("fail to send punch request: %d", error);
		}
		unlockRelaySockaddr();
	}
#endif
#endif
	return ret;
}

int WINAPI my_closesocket(SOCKET s) {
	unmapSocket(s);
	int ret = actual_closesocket(s);
#if DEBUG
	if (ret) {
		int error = WSAGetLastError();
		DEBUG_LOG("error: %d, %d", ret, error);
		WSASetLastError(error);
	}
#endif
	return ret;
}

int WINAPI my_getsockopt(SOCKET s, int level, int optname, char *optval, int *optlen) {
	if (!isSocketMapped(s))
		return actual_getsockopt(s, level, optname, optval, optlen);
	DEBUG_LOG("");
	if (level == SOL_SOCKET && optname == SO_TYPE) {
		if (optval != NULL && optlen != NULL && *optlen >= 4) {
			*(int *)optval = AF_INET;
			*optlen = 4;
			return 0;
		} else {
			WSASetLastError(WSAEFAULT);
			return SOCKET_ERROR;
		}
	}
	return actual_getsockopt(s, level, optname, optval, optlen);
}

int WINAPI my_getsockname(SOCKET s, struct sockaddr *name_original, int *namelen_original) {
	if (!isSocketMapped(s))
		return actual_getsockname(s, name_original, namelen_original);
	DEBUG_LOG("");
	if (name_original == NULL || namelen_original == NULL || *namelen_original < sizeof(struct sockaddr_in)) {
		WSASetLastError(WSAEFAULT);
		return SOCKET_ERROR;
	}
	struct sockaddr_in6 name6;
	int name6len = sizeof(struct sockaddr_in6);
	int ret = actual_getsockname(s, (struct sockaddr *)&name6, &name6len);
	if (ret)
		return ret;
	sockaddr6to4(&name6, (struct sockaddr_in *)name_original);
	*namelen_original = sizeof(struct sockaddr_in);
	return ret;
}

int WINAPI my_getpeername(SOCKET s, struct sockaddr *name_original, int *namelen_original) {
	if (!isSocketMapped(s))
		return actual_getpeername(s, name_original, namelen_original);
	DEBUG_LOG("");
	if (name_original == NULL || namelen_original == NULL || *namelen_original < sizeof(struct sockaddr_in)) {
		WSASetLastError(WSAEFAULT);
		return SOCKET_ERROR;
	}
	struct sockaddr_in6 name6;
	int name6len = sizeof(struct sockaddr_in6);
	int ret = actual_getpeername(s, (struct sockaddr *)&name6, &name6len);
	if (ret)
		return ret;
	sockaddr6to4(&name6, (struct sockaddr_in *)name_original);
	*namelen_original = sizeof(struct sockaddr_in);
	return ret;
}