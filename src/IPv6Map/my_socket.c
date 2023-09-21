#include "my_socket.h"

#include "addr_map.h"
#include "debug.h"
#include "hash_addr.h"
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

#ifdef BUILD_FOR_SOKU
#if BUILD_FOR_SOKU
#define debug_packet_information(buf, size) \
	do { \
		if ((size) >= 1) \
			switch (*(const char *)(buf)) { \
			case 0x1: \
				DEBUG_LOG("HELLO"); \
				break; \
			case 0x3: \
				DEBUG_LOG("OLLEH"); \
				break; \
			case 0x2: \
				DEBUG_LOG("PUNCH"); \
				break; \
			case 0x5: \
				DEBUG_LOG("INIT_REQUEST"); \
				break; \
			case 0x6: \
				DEBUG_LOG("INIT_SUCCESS"); \
				break; \
			case 0x7: \
				if (size >= 5) \
					DEBUG_LOG("INIT_ERROR %d", *(int *)(buf + 1)); \
				break; \
			case 0x8: \
				DEBUG_LOG("REDIRECT"); \
				break; \
			case 0xB: \
				DEBUG_LOG("QUIT"); \
				break; \
			} \
	} while (0);
#else
inline void debugdebug_packet_information(const char *buf, int size) {}
#endif
#else
inline void debugdebug_packet_information(const char *buf, int size) {}
#endif

void punch(SOCKET s, const struct in6_addr *to, uint16_t port, bool second) {
	if (isIPv4MappedIPv6(to)) {
		DEBUG_LOG("an ipv4, doesn't need to punch by ipv6map");
		return;
	}
	DEBUG_LOG("send punch request (%d) to relay", second);
	const struct punch_request request = {'6', PUNCH_FROM_CLIENT, second, *to, port};
	const struct sockaddr_in6 *relay_addr = lockAndReadRelaySockaddr();
	if (actual_sendto(s, (const char *)&request, sizeof(request), 0, (const struct sockaddr *)relay_addr, sizeof(*relay_addr)) == SOCKET_ERROR) {
		int error = WSAGetLastError();
		DEBUG_LOG("fail to send punch request: %d", error);
	}
	unlockRelaySockaddr();
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
	debug_packet_information(out_buf, ret);
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
			if (ret != sizeof(struct punch_request)) {
				DEBUG_LOG("invaild punch requsst size %d, should be %zu", ret, sizeof(struct punch_request));
				break;
			}
			const struct punch_request *request_received = (const struct punch_request *)out_buf;
			if (request_received->sin6_port == 0) {
				DEBUG_LOG("port of PUUNCH_FROM_RELAY is unexpected zero");
				break;
			}
			struct sockaddr_in6 sockaddr = {AF_INET6, request_received->sin6_port, 0, request_received->sin6_addr, 0};
			const struct punch_pingpong data = {'6', PUNCH_PING};
			DEBUG_LOG("send ping for punch");
			if (actual_sendto(s, (const char *)&data, sizeof(data), 0, (const struct sockaddr *)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR) {
				int error = WSAGetLastError();
				DEBUG_LOG("fail to send ping for punch: %d", error);
			}
			if (!out_buf[2])
				punch(s, &sockaddr.sin6_addr, sockaddr.sin6_port, true);
			break;
		case PUNCH_FROM_CLIENT:
			DEBUG_LOG("unexpected punch packet from client! it should be sent to relay.");
			break;
		case V6_SOKU_HELLO:
			if (ret != sizeof(struct v6_soku_hello)) {
				DEBUG_LOG("invaild v6_soku_hello packet size %d, should be %zu", ret, sizeof(struct v6_soku_hello));
				break;
			}
			DEBUG_LOG("receive v6_soku_hello");
			const struct v6_soku_hello *v6_soku_hello_packet = (const struct v6_soku_hello *)out_buf;
			struct soku_hello soku_hello_packet = {1, {AF_INET, v6_soku_hello_packet->peer_port, {0}, {0}}, {AF_INET, v6_soku_hello_packet->target_port, {0}, {0}}};
			memcpy(soku_hello_packet.stuff, v6_soku_hello_packet->stuff, sizeof(soku_hello_packet.stuff));
			if (addr6to4(&(struct in6_addr_with_scope){v6_soku_hello_packet->peer_address6, 0}, &soku_hello_packet.peer_address.sin_addr) != 0) {
				DEBUG_LOG("fail to map to v4");
				break;
			}
			if (addr6to4(&(struct in6_addr_with_scope){v6_soku_hello_packet->target_address6, 0}, &soku_hello_packet.target_address.sin_addr) != 0) {
				DEBUG_LOG("fail to map to v4");
				break;
			}
			memcpy(out_buf, &soku_hello_packet, sizeof(soku_hello_packet));
			return sizeof(soku_hello_packet);
		case V6_SOKU_REDIRECT:
			if (ret != sizeof(struct v6_soku_redirect)) {
				DEBUG_LOG("invaild v6_soku_redirect packet size %d, should be %zu", ret, sizeof(struct v6_soku_redirect));
				break;
			}
			DEBUG_LOG("receive v6_soku_redirect");
			const struct v6_soku_redirect *v6_soku_redirect_packet = (const struct v6_soku_redirect *)out_buf;
			struct soku_redirect soku_redirect_packet = {8, v6_soku_redirect_packet->child_id, {AF_INET, v6_soku_redirect_packet->target_port, {0}, {0}}};
			memcpy(soku_redirect_packet.stuff, v6_soku_redirect_packet->stuff, sizeof(soku_redirect_packet.stuff));
			if (addr6to4(&(struct in6_addr_with_scope){v6_soku_redirect_packet->target_address6, 0}, &soku_redirect_packet.target_address.sin_addr) != 0) {
				DEBUG_LOG("fail to map to v4");
				break;
			}
			punch(s, &v6_soku_redirect_packet->target_address6, v6_soku_redirect_packet->target_port, false);
			memcpy(out_buf, &soku_redirect_packet, sizeof(soku_redirect_packet));
			return sizeof(soku_redirect_packet);
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

#ifdef BUILD_FOR_SOKU
#if BUILD_FOR_SOKU
	if (len >= 1)
		switch (*buf) {
		case 1:
			if (len != sizeof(struct soku_hello)) {
				DEBUG_LOG("invaild soku HELLO packet size %d, shuold be %zu", len, sizeof(struct soku_hello));
				break;
			}
			const struct soku_hello *soku_hello_packet = (const struct soku_hello *)buf;
			if (memcmp(&soku_hello_packet->peer_address, &soku_hello_packet->target_address, sizeof(struct sockaddr_in)) == 0) {
				punch(s, &to.sin6_addr, to.sin6_port, false);
			} else {
				if (!isIPv6MappedIPv4(&soku_hello_packet->peer_address.sin_addr) && !isIPv6MappedIPv4(&soku_hello_packet->target_address.sin_addr))
					break; // don't need to convert
				struct in6_addr_with_scope peer6, target6;
				DEBUG_LOG("send converted soku HELLO with ipv6 address");
				if (addr4to6(&soku_hello_packet->peer_address.sin_addr, &peer6) != 0 || addr4to6(&soku_hello_packet->peer_address.sin_addr, &target6) != 0) {
					DEBUG_LOG("fail to convert to IPv6");
					break;
				}
				struct v6_soku_hello converted_soku_hello
					= {'6', V6_SOKU_HELLO, peer6.sin6_addr, soku_hello_packet->peer_address.sin_port, target6.sin6_addr, soku_hello_packet->target_address.sin_port};
				memcpy(converted_soku_hello.stuff, soku_hello_packet->stuff, sizeof(converted_soku_hello.stuff));
				if (actual_sendto(s, (const char *)&converted_soku_hello, sizeof(converted_soku_hello), 0, (const struct sockaddr *)&to, sizeof(to)) == SOCKET_ERROR) {
					int error = WSAGetLastError();
					DEBUG_LOG("fail to send converted soku HELLO: %d", error);
				}
				return len;
			}
			break;
		case 8:
			if (len != sizeof(struct soku_redirect)) {
				DEBUG_LOG("invaild soku REDIRECT packet size %d, shuold be %zu", len, sizeof(struct soku_redirect));
				break;
			}
			const struct soku_redirect *soku_redirect_packet = (struct soku_redirect *)buf;
#if DEBUG
			wchar_t v4_str[INET_ADDRSTRLEN];
			addrtowstr(&soku_redirect_packet->target_address, v4_str);
#endif
			if (!isIPv6MappedIPv4(&soku_redirect_packet->target_address.sin_addr)) {
				DEBUG_LOG("soku REDIRECT %ls doesn't need to convert", v4_str);
				break; // don't need to convert
			}
			struct in6_addr_with_scope target6;
			DEBUG_LOG("send converted soku REDIRECT %ls wirh ipv6 address", v4_str);
			if (addr4to6(&soku_redirect_packet->target_address.sin_addr, &target6) != 0) {
				DEBUG_LOG("fail to convert to IPv6");
				break;
			}
			struct v6_soku_redirect converted_soku_redirect
				= {'6', V6_SOKU_REDIRECT, soku_redirect_packet->child_id, target6.sin6_addr, soku_redirect_packet->target_address.sin_port};
			memcpy(converted_soku_redirect.stuff, soku_redirect_packet->stuff, sizeof(converted_soku_redirect.stuff));
			if (actual_sendto(s, (const char *)&converted_soku_redirect, sizeof(converted_soku_redirect), 0, (const struct sockaddr *)&to, sizeof(to))
				== SOCKET_ERROR) {
				int error = WSAGetLastError();
				DEBUG_LOG("faid to send converted soku REDIRECT: %d", error);
			}
			return len;
		}
#endif
#endif

	int ret = actual_sendto(s, buf, len, flags, (const struct sockaddr *)&to, tolen);
#if DEBUG
	if (ret == SOCKET_ERROR) {
		int error = WSAGetLastError();
		DEBUG_LOG("error when recvfrom: %d", error);
		WSASetLastError(error);
	} else {
		// DEBUG_LOG("send %d", ret);
	}
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