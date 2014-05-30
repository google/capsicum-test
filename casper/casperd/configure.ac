dnl -*-autoconf-*-
dnl casperd: Autoconf script
dnl (c) 2014 Google, Inc.


AC_PREREQ([2.69])
AC_INIT([casperd],[0.1.0])
AC_CONFIG_SRCDIR([casperd.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE()
AC_USE_SYSTEM_EXTENSIONS

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL

dnl Checks for libraries.
AC_CHECK_LIB([casper], [service_alloc])
AC_CHECK_LIB([caprights], [cap_rights_init])
AC_CHECK_LIB([nv], [nvlist_create])

dnl Checks for header files.
AC_CHECK_HEADER_STDBOOL

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_MEMBER([struct sockaddr_un.sun_len],
		[AC_DEFINE(HAVE_SOCKADDR_SUN_LEN,1,[Have the sockaddr_un.sun_len member.])],
		[],
		[ #include <sys/types.h>
		  #include <sys/un.h>
		])

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero])
AC_CHECK_FUNCS([dup2])
AC_CHECK_FUNCS([select])
AC_CHECK_FUNCS([setproctitle])
AC_CHECK_FUNCS([socket])
AC_SEARCH_LIBS([strlcpy], [bsd])
AC_SEARCH_LIBS([getprocname], [bsd])
AC_SEARCH_LIBS([setprocname], [bsd])
AC_SEARCH_LIBS([flopen], [bsd])
AC_SEARCH_LIBS([closefrom], [bsd])

AC_OUTPUT(Makefile)

