#include <windows.h>
#include <winsock2.h>
#include "debug.h"
#include "ipv6map.h"
#include <memoryapi.h>
#include <ntstatus.h>
#include <shlwapi.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
// clang-format off
// ip2string should be included after winternl
#include <winternl.h>
#include <ip2string.h>
// clang-format on

// from SokuLib
#define TEXT_SECTION_OFFSET 0x00401000
#define TEXT_SECTION_SIZE 0x00456000

#define PATCH_ADDR (0x0040d42a)

char tmp_v4_addr[32];
sockaddr6to4_t sockaddr6to4 = NULL;

LPVOID WINAPI my_GlobalLock(HGLOBAL hMem) {
	const char *str = (char *)GlobalLock(hMem);
	if (!str)
		return (LPVOID)str;
	DEBUG_LOG("clipboard: %s", str);
	struct sockaddr_in6 addr6 = {.sin6_family = AF_INET6, .sin6_flowinfo = 0, .sin6_port = 0};
	struct sockaddr_in addr4 = {.sin_family = AF_INET, .sin_zero = {0}};
	if (RtlIpv6StringToAddressExA(str, &addr6.sin6_addr, (ULONG *)&addr6.sin6_scope_id, &addr6.sin6_port) != STATUS_SUCCESS)
		return (LPVOID)str;
	if (addr6.sin6_port == 0)
		addr6.sin6_port = htons(10800);
	sockaddr6to4(&addr6, &addr4);
	ULONG size = sizeof(tmp_v4_addr);
	if (RtlIpv4AddressToStringExA(&addr4.sin_addr, addr6.sin6_port, tmp_v4_addr, &size) != STATUS_SUCCESS)
		return (LPVOID)str;

	// strip tmp_v4_addr
	int start = 0;
	for (; tmp_v4_addr[start] != '\0'; start++)
		if (!isspace(tmp_v4_addr[start]))
			break;
	if (tmp_v4_addr[start] == '\0')
		return (LPVOID)str;
	for (int i = start + 1; tmp_v4_addr[i] != '\0'; i++)
		if (isspace(tmp_v4_addr[start])) {
			tmp_v4_addr[start] = '\0';
			break;
		}

	DEBUG_LOG("clipboard convert to: %s (port: %hu)", tmp_v4_addr, ntohs(addr6.sin6_port));
	return (LPVOID)(tmp_v4_addr + start);
}

// Based on the code from autopunch mod (https://github.com/SokuDev/SokuMods/blob/master/modules/Autopunch/Autopunch.c)
bool get_ipv6map_dll_path(HMODULE self, wchar_t *ipv6map_dll_path, wchar_t *wfilename) {
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

__declspec(dllexport) bool Initialize(HMODULE hMyModule, HMODULE hParentModule) {
	// load IPv6Map.dll
	for (int i = 0; i < sizeof(IPV6MAP_WFILENAMES) / sizeof(IPV6MAP_WFILENAMES[0]); i++) {
		if (GetModuleHandleW(IPV6MAP_WFILENAMES[i])) {
			DEBUG_LOG("%ls has been loaded outside me, or I was loaded twice.", IPV6MAP_WFILENAMES[i]);
			return false;
		}
		wchar_t ipv6map_dll_path[MAX_PATH];
		if (!get_ipv6map_dll_path(hMyModule, ipv6map_dll_path, IPV6MAP_WFILENAMES[i])) {
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
	if (!sockaddr6to4) {
		DEBUG_LOG("failed to get sockaddr6to4");
		return false;
	}
	DWORD old;
	VirtualProtect((PVOID)TEXT_SECTION_OFFSET, TEXT_SECTION_SIZE, PAGE_EXECUTE_WRITECOPY, &old);
	// asm: call my_GlobalLock
	*(char *)PATCH_ADDR = 0xe8;
	*(void **)(PATCH_ADDR + 1) = ((char *)my_GlobalLock) - (PATCH_ADDR + 5);
	// asm: nop
	*(char *)(PATCH_ADDR + 5) = 0x90;
	VirtualProtect((PVOID)TEXT_SECTION_OFFSET, TEXT_SECTION_SIZE, old, &old);
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
