dnl -*-autoconf-*-
dnl libcaprights: Autoconf script
dnl (c) 2014 Google, Inc.

m4_define([libcaprights_major_version], [0])
m4_define([libcaprights_minor_version], [1])
m4_define([libcaprights_micro_version], [4])

m4_define([libcaprights_major_version], [0])
m4_define([libcaprights_minor_version], [1])
m4_define([libcaprights_micro_version], [3])

AC_PREREQ([2.69])
AC_INIT([libcaprights],[libcaprights_major_version.libcaprights_minor_version.libcaprights_micro_version])
AC_CONFIG_SRCDIR([capsicum.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

LIBCAPRIGHTS_MAJOR_VERSION=libcaprights_major_version
LIBCAPRIGHTS_MINOR_VERSION=libcaprights_minor_version
LIBCAPRIGHTS_MICRO_VERSION=libcaprights_micro_version
AC_SUBST(LIBCAPRIGHTS_MAJOR_VERSION)
AC_SUBST(LIBCAPRIGHTS_MINOR_VERSION)
AC_SUBST(LIBCAPRIGHTS_MICRO_VERSION)

AM_INIT_AUTOMAKE()

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_PROG_LN_S

dnl Checks for libraries.
LT_INIT
AC_SUBST(LIBTOOL_DEPS)

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_HEADER_ASSERT
AC_CHECK_HEADERS([limits.h sys/prctl.h sys/syscall.h linux/seccomp.h linux/capsicum.h])
dnl Check for header files with arch-specific syscall numbers
AC_CHECK_HEADERS([asm/unistd_64_x32.h asm/unistd_64_amd64.h asm/unistd_32_ia32.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_PID_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
