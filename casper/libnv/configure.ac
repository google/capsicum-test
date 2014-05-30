dnl -*-autoconf-*-
dnl libnv: Autoconf script
dnl (c) 2014 Google, Inc.


AC_PREREQ([2.69])
AC_INIT([libnv],[0.1.0])
AC_CONFIG_SRCDIR([nvlist.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE()
AC_USE_SYSTEM_EXTENSIONS

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_PROG_LN_S

dnl Checks for libraries.
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_HEADER_ASSERT
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([sys/param.h])
AC_CHECK_HEADERS([sys/socket.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T
AC_TYPE_INT64_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([struct cmsgcred],[],[],[#include <sys/socket.h>])
AC_CHECK_TYPES([struct ucred],[],[],[#include <sys/socket.h>])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([bzero])
AC_CHECK_FUNCS([select])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([vasprintf])

AC_OUTPUT(Makefile)
