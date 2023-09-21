#ifndef _HASH_ADDR_H_
#define _HASH_ADDR_H_
#ifdef __cplusplus
#include <functional>
#include <xutility>
#endif
#include <windows.h>
#include <in6addr.h>
#include <ws2def.h>

struct in6_addr_with_scope {
	struct in6_addr sin6_addr;
	SCOPE_ID sin6_scope_id;
};

#ifdef __cplusplus
template<> struct std::equal_to<in_addr> {
	bool operator()(const in_addr &a, const in_addr &b) const;
};

template<> struct std::equal_to<in6_addr_with_scope> {
	bool operator()(const in6_addr_with_scope &a, const in6_addr_with_scope &b) const;
};

template<> struct std::hash<in6_addr_with_scope> {
	size_t operator()(const in6_addr_with_scope &a) const;
};
template<> struct std::hash<in_addr> {
	size_t operator()(const in_addr &a) const;
};
#endif
#endif