#include <windows.h>
#include <winsock2.h>
#include "debug.h"
#include "ipv6map.h"
#include "sokuhooks.h"
#include <memoryapi.h>
#include <ntstatus.h>
#include <shlwapi.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// Based on the code from autopunch mod (https://github.com/SokuDev/SokuMods/blob/master/modules/Autopunch/Autopunch.c)
bool GetIPv6MapDllPath(HMODULE self, wchar_t *ipv6map_dll_path, wchar_t *wfilename) {
	if (self == NULL)
		return false;
	if (!GetModuleFileNameW(self, ipv6map_dll_path, MAX_PATH))
		return false;
	if (!PathRemoveFileSpecW(ipv6map_dll_path))
		return false;
	if (!PathAppendW(ipv6map_dll_path, wfilename))
		return false;
	return true;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
	return true;
}

__declspec(dllexport) bool CheckVersion(const BYTE hash[16]) {
	return true;
}

__declspec(dllexport) int getPriority() {
	return 1;
}

__declspec(dllexport) bool Initialize(HMODULE hMyModule, HMODULE hParentModule) {
	// load IPv6Map.dll
	for (int i = 0; i < sizeof(IPV6MAP_WFILENAMES) / sizeof(IPV6MAP_WFILENAMES[0]); i++) {
		if (GetModuleHandleW(IPV6MAP_WFILENAMES[i])) {
			DEBUG_LOG("%ls has been loaded outside me, or I was loaded twice.", IPV6MAP_WFILENAMES[i]);
			return false;
		}
		wchar_t ipv6map_dll_path[MAX_PATH];
		if (!GetIPv6MapDllPath(hMyModule, ipv6map_dll_path, IPV6MAP_WFILENAMES[i])) {
			DEBUG_LOG("failed to get %ls path", IPV6MAP_WFILENAMES[i]);
			continue;
		}
		HMODULE ipv6map_dll;
		if (!(ipv6map_dll = LoadLibraryExW(ipv6map_dll_path, NULL, 0))) {
			DEBUG_LOG("failed to load %ls (%ls)", IPV6MAP_WFILENAMES[i], ipv6map_dll_path);
			continue;
		}
		if (!GetProcAddress(ipv6map_dll, "IPv6MapVersion")) {
			DEBUG_LOG("%ls hasn't IPv6MapVersion. ignore it.", ipv6map_dll_path);
			continue;
		}
		DEBUG_LOG("use %ls", ipv6map_dll_path);
		break;
	}
	sockaddr6to4 = getSockaddr6to4();
	sockaddr4to6 = getSockaddr4to6();
	if (!(sockaddr6to4 && sockaddr6to4)) {
		DEBUG_LOG("failed to get sockaddr6to4 or sockaddr4to6");
		return false;
	}
	SetupHooks();
	return true;
}