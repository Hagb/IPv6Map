#include "inject.h"

#include <windows.h>
#include <winsock2.h>
#include "debug.h"
#include "my_socket.h"
#include <detours.h>
#include <handleapi.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

// FILE *debug;
bool started;

void inject() {
	// if (DEBUG) {
	// 	WARN(L"Injected ipv6map v" STR(AUTOPUNCH_VERSION) " with debug!")
	// 	DEBUG_LOG("starting ipv6map v" STR(AUTOPUNCH_VERSION))
	// }

	started = true;

	DEBUG_LOG("load_start");

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((void **)&actual_recvfrom, (void *)my_recvfrom);
	DetourAttach((void **)&actual_sendto, (void *)my_sendto);
	DetourAttach((void **)&actual_getpeername, (void *)my_getpeername);
	DetourAttach((void **)&actual_getsockname, (void *)my_getsockname);
	DetourAttach((void **)&actual_getsockopt, (void *)my_getsockopt);
	DetourAttach((void **)&actual_closesocket, (void *)my_closesocket);
	DetourAttach((void **)&actual_bind, (void *)my_bind);
	DetourAttach((void **)&actual_socket, (void *)my_socket);
	DetourTransactionCommit();

	DEBUG_LOG("load_end");
}

// void unload() {
// 	DEBUG_LOG("unload_start")

// 	if (started) {
// 		started = false;
// 		// WaitForSingleObject(sockets_mutex, INFINITE);
// 		// CloseHandle(sockets_mutex);

// 		// DEBUG_LOG("unload free sockets: %zu %zu %zu", sockets_len,
// sockets_cap, (size_t)sockets)
// 		// free(sockets);

// 		DEBUG_LOG("unload_detours")
// 		DetourTransactionBegin();
// 		DetourUpdateThread(GetCurrentThread());
// 		DetourDetach((void **)&actual_recvfrom, (void *)my_recvfrom);
// 		DetourDetach((void **)&actual_sendto, (void *)my_sendto);
// 		DetourDetach((void **)&actual_closesocket, (void
// *)my_closesocket); 		DetourDetach((void **)&actual_bind, (void *)my_bind);
// 		DetourTransactionCommit();
// 	}

// 	DEBUG_LOG("unload_end")
// 	// if(debug) {
// 	// 	fclose(debug);
// 	// }
// }
