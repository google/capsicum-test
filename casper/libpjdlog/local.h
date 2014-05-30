#ifndef LOCAL_H
#define LOCAL_H

#include <string.h>
#include <stdint.h>

#include "config.h"

#ifndef HAVE_STRLCAT
size_t strlcat(char * __restrict dst, const char * __restrict src, size_t siz);
#endif

#endif
