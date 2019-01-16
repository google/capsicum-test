#ifndef LOCAL_H
#define LOCAL_H

#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_CLOSEFROM
void closefrom(int lowfd);
#endif

#if defined(__APPLE__)
#include <sys/_endian.h>
#include <util.h>
#elif defined(__FreeBSD__)
#include <sys/endian.h>
#include <libutil.h>
#else

#ifdef HAVE_BSD_SYS_ENDIAN_H
#include <bsd/sys/endian.h>
#else
#include "sys_endian.h"
#endif

#ifdef HAVE_BSD_LIBUTIL_H
#include <bsd/libutil.h>
#endif
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#else
#ifdef HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>
#endif

#ifdef HAVE_BSD_STRING_H
#include <bsd/string.h>
#endif

#ifdef HAVE_BSD_UNISTD_H
#include <bsd/unistd.h>
#endif
#endif

/* Declarations for local replacements */
#ifndef HAVE_ARC4RANDOM_BUF
void arc4random_buf(void *buf, size_t nbytes);
#endif

#ifndef HAVE_CLOSEFROM
void closefrom(int lowfd);
#endif

#ifndef HAVE_FLOPEN
int flopen(const char *path, int flags, ...);
#endif

#ifndef HAVE_GETPROGNAME
const char *getprogname(void);
#endif

#if !defined(HAVE_PIDFILE_OPEN) || !defined(HAVE_PIDFILE_REMOVE) || !defined(HAVE_PIDFILE_WRITE)
#include "pidfile.h"
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char * __restrict dst, const char * __restrict src, size_t siz);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char* src, size_t siz);
#endif

#ifndef _ALIGNBYTES
#define _ALIGNBYTES	(sizeof(int) - 1)
#endif

#ifndef _ALIGN
#define _ALIGN(p)	(((uintptr_t)(p) + _ALIGNBYTES) & ~_ALIGNBYTES)
#endif

#endif
