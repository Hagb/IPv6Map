#ifndef _DEBUG_H_
#define _DEBUG_H_
#define STR_(a) #a
#define STR(a) STR_(a)

#define addrtowstr(psockaddr, wstr_array) \
	do { \
		DWORD len = sizeof(wstr_array);\
		wcscpy((wstr_array), L"(an invaild address!)"); \
		int error = WSAGetLastError(); \
		if (WSAAddressToStringW((struct sockaddr *)(psockaddr), sizeof(*(psockaddr)), NULL, (wstr_array), &len)) \
			WSAGetLastError(); \
		WSASetLastError(error); \
	} while (0)

#ifndef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#define DEBUG 1
#define DEBUG_LOG(fmt, ...) (printf("%s@%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__))

#define DEBUG_ADDR(fmt, sockaddr, ...) \
	(printf("%s@%d: " fmt "%d.%d.%d.%d:%d\n", __func__, __LINE__, ##__VA_ARGS__, (sockaddr)->sin_addr.S_un.S_un_b.s_b1, (sockaddr)->sin_addr.S_un.S_un_b.s_b2, \
		(sockaddr)->sin_addr.S_un.S_un_b.s_b3, (sockaddr)->sin_addr.S_un.S_un_b.s_b4, ntohs((sockaddr)->sin_port)))

#else
#define DEBUG 0
#define DEBUG_LOG(fmt, ...) 0
#define DEBUG_ADDR(fmt, addr, ...) 0
#endif

#define WARN(fmt, ...) \
	do { \
		size_t needed = _snwprintf(NULL, 0, fmt, ##__VA_ARGS__); \
		wchar_t *buf = (wchar_t *)malloc((needed + 1) * 2); \
		_snwprintf(buf, (needed + 1), fmt, ##__VA_ARGS__); \
		MessageBoxW(NULL, buf, L"autopunch", MB_ICONWARNING | MB_OK); \
		free(buf); \
	} while (0)
#endif
