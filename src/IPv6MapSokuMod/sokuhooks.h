#ifndef _SOKUHOOKS_H_
#define _SOKUHOOKS_H_

#include "ipv6map.h"
#include <stdint.h>

extern sockaddr6to4_t sockaddr6to4;
extern sockaddr4to6_t sockaddr4to6;
extern void SetupHooks();
#endif