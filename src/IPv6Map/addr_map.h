#ifndef _ADDR_MAP_H_
#define _ADDR_MAP_H_
#include <winsock2.h>
#include "hash_addr.h"
#include <in6addr.h>
#include <stdbool.h>
#include <stdint.h>
#include <ws2ipdef.h>
// 127.127.0.0/16
#define PREFIX ((127u << 24) + (127u << 16) + (0u << 8) + (0u << 0))
#define PREFIX_LENGTH (16)

#define MASK (0xffffffffu << (32 - PREFIX_LENGTH))
#define MAPPED_IPV4_MAX ((1u << (32 - PREFIX_LENGTH)) - 1)
EXTERN_C __declspec(dllexport) int sockaddr6to4(const struct sockaddr_in6 *in6, struct sockaddr_in *out4);
EXTERN_C __declspec(dllexport) int sockaddr4to6(const struct sockaddr_in *in4, struct sockaddr_in6 *out6);
EXTERN_C int addr4to6(const struct in_addr *in4, struct in6_addr_with_scope *out6);
EXTERN_C int addr6to4(const struct in6_addr_with_scope *in6, struct in_addr *out4);
inline bool isIPv6MappedIPv4(const struct in_addr *addr) {
	return (addr->S_un.S_addr & htonl(MASK)) == htonl(PREFIX);
}
inline bool isIPv4MappedIPv6(const struct in_addr6 *addr6) {
	return ((uint64_t *)addr6->u.Word)[0] == ((uint64_t *)in6addr_v4mappedprefix.u.Word)[0]
		&& ((uint32_t *)addr6->u.Word)[2] == ((uint32_t *)in6addr_v4mappedprefix.u.Word)[2];
}
// EXTERN_C void initialize_add_map();
#endif
