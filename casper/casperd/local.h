#ifndef LOCAL_H
#define LOCAL_H

#include <string.h>
#include <stdint.h>

#include "config.h"

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char* src, size_t siz);
#endif

#endif

