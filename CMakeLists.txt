cmake_minimum_required(VERSION 3.12)
project(ipv6map C CXX)

set(CMAKE_C_STANDARD 11)

# /W4 /WX /Zi /MT /Gy /Gm- /Zl /Od

# DETOURS_TARGET_PROCESSOR=X64
# DETOURS_OPTION_PROCESSOR=X86
# DETOURS_OPTION_BITS=32
add_definitions(-DWINVER=0x0600 -D_WIN32_WINNT=0x0600)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(IPV6MAP_VERSION "0.0.0.1" CACHE "STRING" "IPv6Map output DLL file version")
option(BUILD_FOR_SOKU "build for Touhou Hisoutensoku" OFF)
string(REPLACE "." ", " IPV6MAP_VERSION_COMMA "${IPV6MAP_VERSION}")
configure_file(src/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version.rc
        @ONLY NEWLINE_STYLE CRLF)

add_library(IPv6Map MODULE
        detours/src/detours.cpp
        detours/src/modules.cpp
        detours/src/disasm.cpp
        detours/src/image.cpp
        detours/src/creatwth.cpp
        detours/src/disolx86.cpp
        detours/src/disolx64.cpp
        detours/src/disolia64.cpp
        detours/src/disolarm.cpp
        detours/src/disolarm64.cpp
	src/IPv6Map/inject.c
	src/IPv6Map/hash_addr.cpp
	src/IPv6Map/addr_map.cpp
	src/IPv6Map/my_socket.c
	src/IPv6Map/socket.cpp
	src/IPv6Map/dll_main.c
        ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
target_link_libraries(IPv6Map PRIVATE shlwapi ws2_32 ntdll)
target_include_directories(IPv6Map PRIVATE detours/src)
target_compile_definitions(IPv6Map PRIVATE -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS -DIPV6MAP_VERSION=${IPV6MAP_VERSION} -DBUILD_FOR_SOKU=$<BOOL:${BUILD_FOR_SOKU}>)
target_compile_options(IPv6Map PRIVATE
        "$<$<CONFIG:DEBUG>:/MTd>"
        "$<$<NOT:$<CONFIG:DEBUG>>:/MT>")

if(BUILD_FOR_SOKU)
	add_library(IPv6MapSokuMod MODULE
		src/IPv6MapSokuMod/sokumod_main.c
		${CMAKE_CURRENT_BINARY_DIR}/version.rc)
	target_link_libraries(IPv6MapSokuMod PRIVATE shlwapi ws2_32 ntdll)
	target_include_directories(IPv6MapSokuMod PRIVATE src)
	target_compile_definitions(IPv6MapSokuMod PRIVATE -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS -DIPV6MAP_VERSION=${IPV6MAP_VERSION})
	target_compile_options(IPv6MapSokuMod PRIVATE
		"$<$<CONFIG:DEBUG>:/MTd>"
		"$<$<NOT:$<CONFIG:DEBUG>>:/MT>")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(TARGET_FILE_BITS 64)
else()
    set(TARGET_FILE_BITS 86)
endif()
if(CMAKE_BUILD_TYPE STREQUAL Debug)
    set(TARGET_FILE_BUILD dbg)
else()
    set(TARGET_FILE_BUILD rel)
endif()
