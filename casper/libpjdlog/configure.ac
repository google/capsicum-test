dnl -*-autoconf-*-
dnl libpjdlog: Autoconf script
dnl (c) 2014 Google, Inc.


AC_PREREQ([2.69])
AC_INIT([libpjdlog],[0.1.0])
AC_CONFIG_SRCDIR([pjdlog.c])
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
AC_SEARCH_LIBS([strlcat], [libbsd])

dnl Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h syslog.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T

# Checks for library functions.
AC_CHECK_FUNCS([strerror])

AC_OUTPUT(Makefile)

