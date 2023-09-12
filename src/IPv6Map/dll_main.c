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

#define STRINGIZE(s) #s

EXTERN_C __declspec(dllexport) const char IPv6MapVersion[] = STRINGIZE(IPV6MAP_VERSION);