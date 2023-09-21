#include "socket_manage.h"

#include "debug.h"
#include "my_socket.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <in6addr.h>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#define IPV6_ADDR(a, b, c, d, e, f, g, h) \
	{ ntohs((a)), ntohs((b)), ntohs((c)), ntohs((d)), ntohs((e)), ntohs((f)), ntohs((g)), ntohs((h)) }
#define DEFAULT_RELAY_IP IPV6_ADDR(0x2409, 0x8a55, 0xc8c1, 0x7d10, 0x9840, 0x1d32, 0x28a1, 0xc045)
#define RELAY_DOMAIN ("v6relay.hagb.name")
#define RELAY_PORT (12321)
std::shared_mutex keep_alive_mutex;
std::thread *keep_alive_thread = nullptr;
std::thread *update_relay_thread = nullptr;
bool keep_alive_started = false;
std::unordered_map<SOCKET, uint16_t> socket_set;
std::shared_mutex socket_mutex;
sockaddr_in6 relay_sockaddr;
EXTERN_C int isSocketMapped(SOCKET socket) {
	socket_mutex.lock_shared();
	auto iter = socket_set.find(socket);
	bool ret = iter != socket_set.end();
	socket_mutex.unlock_shared();
	return ret;
}
EXTERN_C void unmapSocket(SOCKET socket) {
	socket_mutex.lock();
	socket_set.erase(socket);
	socket_mutex.unlock();
}
EXTERN_C void mapSocket(SOCKET socket, uint16_t hport) {
	socket_mutex.lock();
	auto result = socket_set.insert({socket, hport});
	if (!result.second)
		result.first->second = hport;
	socket_mutex.unlock();
}

const sockaddr_in6 *lockAndReadRelaySockaddr() {
	keep_alive_mutex.lock_shared();
	return &relay_sockaddr;
}

void unlockRelaySockaddr() {
	keep_alive_mutex.unlock_shared();
}

void ping_relay() {
	socket_mutex.lock_shared();
	for (auto iter = socket_set.begin(); iter != socket_set.end(); iter++)
		if (iter->second) {
			const char data[] = {'6', PUNCH_PING};
			keep_alive_mutex.lock_shared();
#if DEBUG
			wchar_t v6str[INET6_ADDRSTRLEN];
			addrtowstr(&relay_sockaddr, v6str);
			DEBUG_LOG("[::]:%d ping %ls", iter->second, v6str);
#endif
			if (actual_sendto(iter->first, data, sizeof(data), 0, (const struct sockaddr *)&relay_sockaddr, sizeof(relay_sockaddr)) == SOCKET_ERROR) {
				int error = WSAGetLastError();
				DEBUG_LOG("error when pinging: %d", error);
			}
			keep_alive_mutex.unlock_shared();
		}
	socket_mutex.unlock_shared();
}

void update_relay_address() {
	using namespace std::chrono_literals;
	for (;; std::this_thread::sleep_for(2000ms)) {
		struct addrinfo *result = NULL;
		struct addrinfo hints = {0, AF_INET6, 0, 0, NULL, NULL, NULL, NULL};
		if (GetAddrInfoA(RELAY_DOMAIN, NULL, &hints, &result) != 0) {
			int error = WSAGetLastError();
			DEBUG_LOG("fail to query AAAA record of %s: %d", RELAY_DOMAIN, error);
			continue;
		}
		bool got = false;
		for (struct addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next)
			if (ptr->ai_family == AF_INET6) {
				if (ptr->ai_addrlen != sizeof(relay_sockaddr)) {
					DEBUG_LOG("unexpected AAAA address size %zu, should be %zu", ptr->ai_addrlen, sizeof(relay_sockaddr));
					continue;
				}
				wchar_t v6[INET6_ADDRSTRLEN];
				addrtowstr((const sockaddr_in6 *)ptr->ai_addr, v6);
				DEBUG_LOG("get AAAA record of %s: %ls", RELAY_DOMAIN, v6);
				keep_alive_mutex.lock();
				memcpy(&relay_sockaddr, ptr->ai_addr, sizeof(relay_sockaddr));
				relay_sockaddr.sin6_port = htons(RELAY_PORT);
				keep_alive_mutex.unlock();
				got = true;
				ping_relay();
				break;
			}
		FreeAddrInfoA(result);
		if (got)
			break;
	}
}

void keep_alive() {
	using namespace std::chrono_literals;
	while (true) {
		ping_relay();
		std::this_thread::sleep_for(2000ms);
	}
}

void startKeepAliveIfNotStarted() {
	if (keep_alive_started)
		return;
	keep_alive_mutex.lock();
	if (keep_alive_thread) {
		keep_alive_mutex.unlock();
		return;
	}
	relay_sockaddr = {AF_INET6, 0, 0, {0}, 0};
	uint16_t in6addr[] = DEFAULT_RELAY_IP;
	relay_sockaddr.sin6_port = htons(RELAY_PORT);
	for (int i = 0; i < 8; i++)
		relay_sockaddr.sin6_addr.u.Word[i] = in6addr[i];
	keep_alive_thread = new std::thread(keep_alive);
	update_relay_thread = new std::thread(update_relay_address);
	keep_alive_started = true;
	keep_alive_mutex.unlock();
}