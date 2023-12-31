// TODO: unused addresses collection

#include "addr_map.h"

#include <winsock2.h>
#include "debug.h"
#include "hash_addr.h"
#include <assert.h>
#include <cstdint>
#include <mstcpip.h>
#include <mutex>
#include <unordered_map>

std::mutex ip_mutex;
std::unordered_map<in_addr, in6_addr_with_scope> map4to6;
unsigned int map4endding = 0;
std::unordered_map<in6_addr_with_scope, in_addr> map6to4;

#if (MASK & PREFIX) != PREFIX
#error length of prefix > LENGTH length.
#endif

int addr4to6(const in_addr *in4, in6_addr_with_scope *out6) {
	if (in4->S_un.S_addr == 0) {
		// if in4 is 0.0.0.0
		DEBUG_LOG("0.0.0.0");
		out6->sin6_scope_id.Value = 0;
		((uint64_t *)out6->sin6_addr.u.Word)[0] = ((uint64_t *)out6->sin6_addr.u.Word)[1] = 0;
		return 0;
	}
	if (!(isIPv6MappedIPv4(in4))) {
		// if in4 is not mapped ipv4
		IN6_SET_ADDR_V4MAPPED(&out6->sin6_addr, in4);
		out6->sin6_scope_id.Value = 0;
		IN4_UNCANONICALIZE_SCOPE_ID(in4, &(out6->sin6_scope_id));
		return 0;
	}
	ip_mutex.lock();
	auto iter = map4to6.find(*in4);
	if (iter == map4to6.end()) {
		ip_mutex.unlock();
		return 1;
	}
	*out6 = iter->second;
	ip_mutex.unlock();
	return 0;
}

int addr6to4(const in6_addr_with_scope *in6, in_addr *out4) {
	if (((uint64_t *)in6->sin6_addr.u.Word)[0] == 0 && ((uint64_t *)in6->sin6_addr.u.Word)[1] == 0) {
		// if in6 is [::]
		out4->S_un.S_addr = 0;
		return 0;
	}
	if (isIPv4MappedIPv6(&in6->sin6_addr)) {
		// if in6 is an IPv4 mapped address
		out4->S_un.S_addr = ((uint32_t *)in6->sin6_addr.u.Word)[3];
		return 0;
	}
	ip_mutex.lock();
	auto iter = map6to4.find(*in6);
	if (iter == map6to4.end()) {
		in_addr addr4;
		do {
			if (map4endding == MAPPED_IPV4_MAX) {
				ip_mutex.unlock();
				return 1;
			}
			addr4.S_un.S_addr = htonl(PREFIX | (++map4endding));
		} while (map4to6.find(addr4) != map4to6.end() && (DEBUG_LOG("Unexpected usage of IPv6-mapped IPv4 addr"), 1));
		map4to6.insert({addr4, *in6});
		map6to4.insert({*in6, addr4});
		*out4 = addr4;
	} else {
		*out4 = iter->second;
	}
	ip_mutex.unlock();
	return 0;
}

__declspec(dllexport) int sockaddr6to4(const sockaddr_in6 *in6, sockaddr_in *out4) {
	out4->sin_family = AF_INET;
	out4->sin_port = in6->sin6_port;
	*(uint64_t *)out4->sin_zero = 0;
	int ret = addr6to4((in6_addr_with_scope *)(&in6->sin6_addr), &out4->sin_addr);
	// return value to do
#if DEBUG
	// wchar_t v4[INET_ADDRSTRLEN];
	// wchar_t v6[INET6_ADDRSTRLEN];
	// addrtowstr(in6, v6);
	// addrtowstr(out4, v4);
	// DEBUG_LOG("v6 addr: %ls ,v4 addr: %ls", v6, v4);
#endif
	return ret;
}

__declspec(dllexport) int sockaddr4to6(const sockaddr_in *in4, sockaddr_in6 *out6) {
	out6->sin6_family = AF_INET6;
	out6->sin6_flowinfo = 0;
	out6->sin6_port = in4->sin_port;
	int ret = addr4to6(&in4->sin_addr, (in6_addr_with_scope *)(&out6->sin6_addr));
#if DEBUG
	if (ret) {
		wchar_t v4[INET_ADDRSTRLEN];
		addrtowstr(in4, v4);
		DEBUG_LOG("convert failed: v4 addr: %ls ", v4);
	} else {
		// wchar_t v4[INET_ADDRSTRLEN];
		// wchar_t v6[INET6_ADDRSTRLEN];
		// addrtowstr(in4, v4);
		// addrtowstr(out6, v6);
		// DEBUG_LOG("v4 addr: %ls ,v6 addr: %ls", v4, v6);
	}
#endif
	return ret;
}

// int get_sockaddr4_type(sockaddr_in);

// int get_sockaddr6_type(sockaddr_in6);