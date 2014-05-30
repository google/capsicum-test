dnl -*-autoconf-*-
dnl libcapsicum: Autoconf script
dnl (c) 2014 Google, Inc.


AC_PREREQ([2.69])
AC_INIT([libcapsicum],[0.1.0])
AC_CONFIG_SRCDIR([libcapsicum.c])
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
AC_CHECK_LIB([caprights], [cap_rights_init])
AC_CHECK_LIB([nv], [nvlist_create])
AC_SEARCH_LIBS([strlcpy], [libbsd])
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_HEADER_ASSERT
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([nv.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([sys/param.h])
AC_CHECK_HEADERS([sys/socket.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T
AC_TYPE_INT64_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T
AC_CHECK_MEMBER([struct sockaddr_un.sun_len],
		[AC_DEFINE(HAVE_SOCKADDR_SUN_LEN,1,[Have the sockaddr_un.sun_len member.])],
		[],
		[ #include <sys/types.h>
		  #include <sys/un.h>
		])
AC_CHECK_MEMBER([struct passwd.pw_change],
		[AC_DEFINE(HAVE_PASSWD_PW_CHANGE,1,[Have the passwd.pw_change member.])],
		[],
		[ #include <pwd.h>
		])
AC_CHECK_MEMBER([struct passwd.pw_class],
		[AC_DEFINE(HAVE_PASSWD_PW_CLASS,1,[Have the passwd.pw_class member.])],
		[],
		[ #include <pwd.h>
		])
AC_CHECK_MEMBER([struct passwd.pw_expire],
		[AC_DEFINE(HAVE_PASSWD_PW_EXPIRE,1,[Have the passwd.pw_expire member.])],
		[],
		[ #include <pwd.h>
		])
AC_CHECK_MEMBER([struct passwd.pw_fields],
		[AC_DEFINE(HAVE_PASSWD_PW_FIELDS,1,[Have the passwd.pw_fields member.])],
		[],
		[ #include <pwd.h>
		])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([bzero])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([select])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strdup])
AC_REPLACE_FUNCS([strlcpy])

AC_OUTPUT(Makefile)
