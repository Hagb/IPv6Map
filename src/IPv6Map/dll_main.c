#include <windows.h>
#include "inject.h"

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		inject();
	} else if (dwReason == DLL_PROCESS_DETACH) {
		// todo: unload
	}
	return TRUE;
}

// https://stackoverflow.com/a/196093
#define _QUOTE_(s) #s
#define _STR_(s) _QUOTE_(s)

__declspec(dllexport) const char IPv6MapVersion[] = _STR_(IPV6MAP_VERSION);