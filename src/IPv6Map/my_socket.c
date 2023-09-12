#include "my_socket.h"

#include "addr_map.h"
#include "debug.h"
#include "socket.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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
		DEBUG_LOG("trace: %x", traces[i]);
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
		DEBUG_LOG("failed to disable ipv6 only: %d , fallback to ipv4", WSAGetLastError());
		if (actual_closesocket(ret)) {
			WSAGetLastError(); // ignore
		}
		return actual_socket(af_original, type, protocol);
	}
	mapSocket(ret);
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
		wchar_t v4[32];
		wchar_t v6[96];
		unsigned long v4len = 32;
		unsigned long v6len = 96;
		int error = WSAGetLastError();
		if (WSAAddressToStringW(name_original, sizeof(struct sockaddr_in), NULL, v4, &v4len))
			WSAGetLastError();
		if (WSAAddressToStringW(&name6, sizeof(struct sockaddr_in6), NULL, v6, &v6len))
			WSAGetLastError();
		v6[95] = v4[31] = 0;
		DEBUG_LOG("error when bind: %d, %d. v4 addr: %ls ,v6 addr: %ls", ret, error, v4, v6);
		WSASetLastError(error);
	}
#endif
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
	DEBUG_LOG("recv %d", ret);
	sockaddr6to4(&from, (struct sockaddr_in *)from_original);
	if (fromlen_original != NULL)
		*fromlen_original = sizeof(struct sockaddr_in);
	return ret;
}

int WINAPI my_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to_original, int tolen_original) {
	if (!isSocketMapped(s))
		return actual_sendto(s, buf, len, flags, to_original, tolen_original);
	DEBUG_LOG("");
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
		DEBUG_LOG("send %d", ret);
	}
#endif
	return ret;
}

int WINAPI my_closesocket(SOCKET s) {
	int ret = actual_closesocket(s);
	if (!ret)
		unmapSocket(s);
#if DEBUG
	else {
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