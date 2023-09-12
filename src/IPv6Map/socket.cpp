#include "socket.h"

#include "debug.h"
#include <mutex>
#include <unordered_set>
std::unordered_set<SOCKET> socket_set;
std::mutex socket_mutex;
EXTERN_C int isSocketMapped(SOCKET socket) {
	socket_mutex.lock();
	auto iter = socket_set.find(socket);
	bool ret = iter != socket_set.end();
	socket_mutex.unlock();
	return ret;
}
EXTERN_C void unmapSocket(SOCKET socket) {
	socket_mutex.lock();
	DEBUG_LOG("%u", socket);
	socket_set.erase(socket);
	socket_mutex.unlock();
}
EXTERN_C void mapSocket(SOCKET socket) {
	socket_mutex.lock();
	DEBUG_LOG("%u", socket);
	socket_set.insert(socket);
	socket_mutex.unlock();
}