#include "sokuhooks.h"

#include "debug.h"
#include "ipv6map.h"
#include <assert.h>
#include <ntstatus.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
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

#define GLOBALLOCK_PATCH_ADDR ((void *)0x0040d42au)
#define BEFORE_RENDER_ADDR ((void *)0x004129abu)
#define ADDRESS_TXT_CREATEFILE_ADDR ((void *)0x00447774u)

sockaddr6to4_t sockaddr6to4 = NULL;
sockaddr4to6_t sockaddr4to6 = NULL;
void *const fun_004088b0_calls[] = {(void *)0x00447c3cu, (void *)0x0044903eu};
const char **const original_suffixes[] = {(void *)0x00447899, (void *)0x00447929};

char tmp_v4_addr[INET_ADDRSTRLEN] = {'\0'};
char ipv6_suffix[INET6_ADDRSTRLEN + sizeof("<!---->") - 1] = {'\0'};

bool String4ToHuman(const char *str4, char *str, ULONG *const size) {
	struct sockaddr_in6 addr6 = {.sin6_family = AF_INET6, .sin6_flowinfo = 0, .sin6_port = 0};
	struct sockaddr_in addr4 = {.sin_family = AF_INET, .sin_zero = {0}};
	if (RtlIpv4StringToAddressExA(str4, 0, &addr4.sin_addr, &addr4.sin_port) != STATUS_SUCCESS)
		goto fail;
	if (addr4.sin_port == 0)
		addr4.sin_port = htons(10800);
	if (sockaddr4to6(&addr4, &addr6) != 0)
		goto fail;
	if (((uint64_t *)addr6.sin6_addr.u.Word)[0] == ((uint64_t *)in6addr_v4mappedprefix.u.Word)[0]
		&& ((uint32_t *)addr6.sin6_addr.u.Word)[2] == ((uint32_t *)in6addr_v4mappedprefix.u.Word)[2])
		//  if addr6 is an (RFC) IPv4 mapped address
		goto fail;
	if (((uint64_t *)addr6.sin6_addr.u.Word)[0] == 0 && ((uint64_t *)addr6.sin6_addr.u.Word)[1] == 0)
		goto fail;
	char addr6_str[INET6_ADDRSTRLEN];
	ULONG size6 = sizeof(addr6_str);
	if (RtlIpv6AddressToStringExA(&addr6.sin6_addr, addr6.sin6_scope_id, addr6.sin6_port, addr6_str, &size6) != STATUS_SUCCESS)
		goto fail;
	if (*size < size6)
		goto fail;
	memcpy(str, addr6_str, *size = size6);
	return true;
fail:
	*size = 0;
	return false;
}

bool String6To4(const char *str6, char *str4, ULONG *const size4) {
	struct sockaddr_in6 addr6 = {.sin6_family = AF_INET6, .sin6_flowinfo = 0, .sin6_port = 0};
	struct sockaddr_in addr4 = {.sin_family = AF_INET, .sin_zero = {0}};
	if (RtlIpv6StringToAddressExA(str6, &addr6.sin6_addr, (ULONG *)&addr6.sin6_scope_id, &addr6.sin6_port) != STATUS_SUCCESS) {
		*size4 = 0;
		return false;
	}
	if (addr6.sin6_port == 0)
		addr6.sin6_port = htons(10800);
	if (sockaddr6to4(&addr6, &addr4) != 0) {
		*size4 = 0;
		return false;
	}
	return RtlIpv4AddressToStringExA(&addr4.sin_addr, addr6.sin6_port, str4, size4) == STATUS_SUCCESS;
}

LPVOID WINAPI my_GlobalLock(HGLOBAL hMem) {
	const char *str = (char *)GlobalLock(hMem);
	if (!str)
		return (LPVOID)str;
	DEBUG_LOG("clipboard: %s", str);

	// strip str
	while (isspace(*str) && *str != '\0')
		str++;
	if (*str == '\0')
		return (LPVOID)str;
	int stripped_length = strlen(str) - 1;
	while (isspace(str[stripped_length]))
		stripped_length--;
	stripped_length++;
	if (stripped_length + 1 > INET6_ADDRSTRLEN)
		return (LPVOID)str;
	char stripped_str[INET6_ADDRSTRLEN];
	memcpy(stripped_str, str, stripped_length);
	stripped_str[stripped_length] = '\0';

	ULONG size = sizeof(tmp_v4_addr);
	return String6To4(stripped_str, tmp_v4_addr, &size) ? (LPVOID)tmp_v4_addr : (LPVOID)str;
}

uint32_t __cdecl my_FUN_004088b0(uint32_t param1, uint32_t param2, const char *suffix) {
	DEBUG_LOG("suffix %s", suffix);
	size_t original_length = strlen(suffix);
	char *new_suffix = malloc(original_length + sizeof(ipv6_suffix));
	memcpy(new_suffix, ipv6_suffix, sizeof(ipv6_suffix) - 1);
	memcpy(new_suffix + sizeof(ipv6_suffix) - 1, suffix, original_length + 1);
	return ((uint32_t(__cdecl *)(uint32_t param1, uint32_t param2, const char *suffix))(0x004088b0u))(param1, param2, new_suffix);
}

void ReplaceAddresses(char *buffer, bool (*converter)(const char *, char *, ULONG *), const char *pad_l, const char *pad_r, bool is_v6) {
	DEBUG_LOG("catch: %s", buffer);
	const size_t len_pad_l = strlen(pad_l);
	const size_t len_pad_r = strlen(pad_r);
	assert(len_pad_l || len_pad_r);
	for (char *suffix; (suffix = strstr(buffer, ipv6_suffix)); buffer = suffix + sizeof(ipv6_suffix) - 1) {
		char *end_of_ip = suffix - 1;
		for (; buffer <= end_of_ip; end_of_ip--) {
			if (!isspace(*end_of_ip) || *end_of_ip == '\n' || *end_of_ip == '\r')
				break;
		}
		end_of_ip++;
		char *start_of_ip = end_of_ip - 1;
		for (; buffer <= start_of_ip; start_of_ip--) {
			if (*start_of_ip == '.' || *start_of_ip == ':' || ('0' <= *start_of_ip && *start_of_ip <= '9'))
				continue;
			if (is_v6)
				if (('a' <= *start_of_ip && *start_of_ip <= 'z') || ('A' <= *start_of_ip && *start_of_ip <= 'Z') || strchr(":[]%", *start_of_ip))
					continue;
			break;
		}
		start_of_ip++;
		char old_end_char = *end_of_ip;
		*end_of_ip = '\0';
		DEBUG_LOG("ip: %s", start_of_ip);

		ULONG size = suffix + (sizeof(ipv6_suffix) - 1) - len_pad_l - len_pad_r - start_of_ip + 1;
		if (!converter(start_of_ip, start_of_ip, &size)) {
			*end_of_ip = old_end_char;
			continue;
		}
		DEBUG_LOG("map to %s", start_of_ip);
		memcpy(start_of_ip + size - 1, pad_l, len_pad_l);
		for (char *p = start_of_ip + size - 1 + len_pad_l; p < suffix + sizeof(ipv6_suffix) - 1 - len_pad_r; p++)
			*p = ' ';
		memcpy(suffix + sizeof(ipv6_suffix) - 1 - len_pad_r, pad_r, len_pad_r);
	}
}

void __stdcall replace4toHuman(char *buffer) {
	ReplaceAddresses(buffer, String4ToHuman, "<!--", "-->", false);
}

static const unsigned int ifLe = 0x00412a23;
static const unsigned int ifGt = 0x004129b3;
__declspec(naked) void beforeRender() {
	__asm {
		mov edx, [esp+0x10]; // from soku
		test edx, edx; // from soku
        jle jleto_lab;
        push eax;
        push ebx;
        push ecx;
        push edx;
        push edi;
        push esi;
        push ebx; // buffer
		call replace4toHuman;
        pop esi;
        pop edi;
        pop edx;
        pop ecx;
        pop ebx;
        pop eax;
        jmp [ifGt];
        jleto_lab:;
        jmp [ifLe];
	}
}

HANDLE __stdcall my_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	assert(dwDesiredAccess == FILE_READ_DATA);
	assert(dwShareMode == FILE_SHARE_READ);
	assert(lpSecurityAttributes == NULL);
	assert(dwCreationDisposition == OPEN_EXISTING);
	assert(dwFlagsAndAttributes == FILE_ATTRIBUTE_NORMAL);
	assert(hTemplateFile == NULL);
	HANDLE address_txt = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	if (address_txt == INVALID_HANDLE_VALUE)
		return address_txt;
	DWORD size = GetFileSize(address_txt, NULL);
	if (size == INVALID_FILE_SIZE) {
		GetLastError();
		return address_txt;
	}
	assert(size < 1024 * 1024 * 64);
	char *buffer = malloc((size_t)size + 1);
	if (!ReadFile(address_txt, buffer, (size_t)size, NULL, NULL)) {
		free(buffer);
		return address_txt;
	}
	buffer[size] = '\0';
	CloseHandle(address_txt);
	HANDLE address_tmp_txt
		= CreateFileA(".address.txt.tmp", FILE_WRITE_DATA, FILE_SHARE_WRITE | FILE_READ_DATA, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (address_tmp_txt == INVALID_HANDLE_VALUE) {
		free(buffer);
		return address_tmp_txt;
	}
	char *next_token = NULL;
	char *token = NULL;
	char *line_buffer = malloc((size_t)size + sizeof(ipv6_suffix));
	if ((token = strtok_s(buffer, "\r\n", &next_token)))
		do {
			if (*token == '\0')
				continue;
			strcpy(line_buffer, token);
			strcat(line_buffer, ipv6_suffix);
			DEBUG_LOG("line_buffer: %s", line_buffer);
			ReplaceAddresses(line_buffer, String6To4, " ", " ", true);
			DEBUG_LOG("converted line_buffer: %s", line_buffer);
			WriteFile(address_tmp_txt, line_buffer, strlen(line_buffer), NULL, NULL);
			WriteFile(address_tmp_txt, "\r\n", 2, NULL, NULL);
		} while ((token = strtok_s(NULL, "\r\n", &next_token)));
	DEBUG_LOG("convert ok! reopen the file");
	CloseHandle(address_tmp_txt);
	free(buffer);
	free(line_buffer);
	return CreateFileA(".address.txt.tmp", dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
// Tamper* functions is from SokuLib
inline void TamperNearJmpOpr(void *addr, const void *targetFct) {
	*(int *)((char *)addr + 1) = (char *)targetFct - ((char *)addr + 5);
}

inline void TamperNearJmp(void *addr, const void *targetFct) {
	*(char *)addr = 0xE9;
	TamperNearJmpOpr(addr, targetFct);
}

inline void TamperNearCall(void *addr, const void *targetFct) {
	*(char *)addr = 0xE8;
	TamperNearJmpOpr(addr, targetFct);
}

inline void TamperNop(void *addr) {
	*(char *)addr = 0x90;
}

void HookAddressSuffixes() {
#define left "<!-- address suffix padded with spaces"
#define right "end -->"
	memcpy(ipv6_suffix, left, sizeof(left) - 1);
	for (int i = sizeof(left) - 1; i < sizeof(ipv6_suffix) - sizeof(right); i++)
		ipv6_suffix[i] = ' ';
	memcpy(ipv6_suffix + sizeof(ipv6_suffix) - sizeof(right), right, sizeof(right));
#undef right
#undef left
	for (int i = 0; i < sizeof(fun_004088b0_calls) / sizeof(*fun_004088b0_calls); i++)
		TamperNearCall(fun_004088b0_calls[i], my_FUN_004088b0);

	for (int i = 0; i < sizeof(original_suffixes) / sizeof(*original_suffixes); i++) {
		size_t original_length = strlen(*original_suffixes[i]);
		char *new_suffix = malloc(original_length + sizeof(ipv6_suffix));
		memcpy(new_suffix, ipv6_suffix, sizeof(ipv6_suffix) - 1);
		memcpy(new_suffix + sizeof(ipv6_suffix) - 1, *original_suffixes[i], original_length + 1);
		*original_suffixes[i] = new_suffix;
		((char *)original_suffixes[i])[-2] = sizeof(ipv6_suffix) + original_length - 1;
	}
}

void HookFileIO() {
	TamperNearCall(ADDRESS_TXT_CREATEFILE_ADDR, my_CreateFileA);
	TamperNop((char *)ADDRESS_TXT_CREATEFILE_ADDR + 5);
	// TODO: hook reading and writing configex123.ini.
}

void SetupHooks() {
	DWORD old;

	VirtualProtect((PVOID)TEXT_SECTION_OFFSET, TEXT_SECTION_SIZE, PAGE_EXECUTE_WRITECOPY, &old);
	// asm: call my_GlobalLock
	TamperNearCall(GLOBALLOCK_PATCH_ADDR, my_GlobalLock);
	// asm: nop
	TamperNop((char *)GLOBALLOCK_PATCH_ADDR + 5);
	// asm: jmp beforeRender
	TamperNearJmp(BEFORE_RENDER_ADDR, beforeRender);
	HookAddressSuffixes();
	HookFileIO();
	VirtualProtect((PVOID)TEXT_SECTION_OFFSET, TEXT_SECTION_SIZE, old, &old);
}