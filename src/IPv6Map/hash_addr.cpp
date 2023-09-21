#include "hash_addr.h"

#include <cstdint>
#include <functional>
size_t std::hash<in6_addr_with_scope>::operator()(const in6_addr_with_scope &a) const {
	return std::hash<std::uint64_t>()(((std::uint64_t *)&a.sin6_addr)[0]) ^ std::hash<std::uint64_t>()(((std::uint64_t *)&a.sin6_addr)[1])
		^ std::hash<std::uint64_t>()(a.sin6_scope_id.Value);
}

size_t std::hash<in_addr>::operator()(const in_addr &a) const {
	return std::hash<ULONG>()(a.S_un.S_addr);
}

bool std::equal_to<in_addr>::operator()(const in_addr &a, const in_addr &b) const {
	return a.S_un.S_addr == b.S_un.S_addr;
}

bool std::equal_to<in6_addr_with_scope>::operator()(const in6_addr_with_scope &a, const in6_addr_with_scope &b) const {
	return ((uint64_t *)a.sin6_addr.u.Word)[0] == ((uint64_t *)(b.sin6_addr.u.Word))[0]
		&& ((uint64_t *)a.sin6_addr.u.Word)[1] == ((uint64_t *)(b.sin6_addr.u.Word))[1] && a.sin6_scope_id.Value == b.sin6_scope_id.Value;
}