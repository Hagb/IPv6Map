#ifndef _ADDR_MAP_H_
#define _ADDR_MAP_H_
#include "hash_addr.h"
#include <in6addr.h>
#include <stdint.h>
#include <ws2ipdef.h>
EXTERN_C __declspec(dllexport) int sockaddr6to4(const struct sockaddr_in6 *in6, struct sockaddr_in *out4);
EXTERN_C __declspec(dllexport) int sockaddr4to6(const struct sockaddr_in *in4, struct sockaddr_in6 *out6);
EXTERN_C int addr4to6(const struct in_addr *in4, struct in_addr6_with_scope *out6);
EXTERN_C int addr6to4(const struct in_addr6_with_scope *in6, struct in_addr *out4);
// EXTERN_C void initialize_add_map();
#endif
