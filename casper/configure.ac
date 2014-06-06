dnl -*-autoconf-*-
dnl Casper: Autoconf script
dnl (c) 2014 Google, Inc.


AC_PREREQ([2.69])
AC_INIT([casper],[0.1.0])
AC_CONFIG_SRCDIR([src/casperd/casperd.c])
AC_CONFIG_LIBOBJ_DIR([src])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE()
AC_USE_SYSTEM_EXTENSIONS

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S

dnl Checks for libraries.
AC_CHECK_LIB([caprights], [cap_rights_limit])
AC_SEARCH_LIBS([closefrom], [bsd])
AC_SEARCH_LIBS([flopen], [bsd])
AC_SEARCH_LIBS([getprogname], [bsd])
AC_SEARCH_LIBS([pidfile_open], [bsd])
AC_SEARCH_LIBS([pidfile_remove], [bsd])
AC_SEARCH_LIBS([pidfile_write], [bsd])
AC_SEARCH_LIBS([strlcat], [bsd])
AC_SEARCH_LIBS([strlcpy], [bsd])

AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_HEADER_ASSERT
AC_CHECK_HEADERS([bsd/stdlib.h bsd/string.h bsd/libutil.h bsd/unistd.h bsd/sys/endian.h])
dnl src/libnv/
AC_CHECK_HEADERS([fcntl.h unistd.h sys/param.h sys/socket.h])
dnl src/libjdlog/
AC_CHECK_HEADERS([arpa/inet.h libutil.h limits.h netinet/in.h printf.h stdint.h stdlib.h string.h sys/socket.h syslog.h unistd.h])
dnl src/libcapsicum/
AC_CHECK_HEADERS([fcntl.h netdb.h unistd.h sys/param.h sys/socket.h])
dnl src/libcasper/
AC_CHECK_HEADERS([fcntl.h unistd.h sys/capsicum.h sys/socket.h])
dnl src/casper/
AC_CHECK_HEADERS([paths.h])
dnl src/
AC_CHECK_HEADERS([stddef.h sys/file.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T
AC_TYPE_INT64_T
AC_TYPE_UINT32_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([struct cmsgcred],[],[],[#include <sys/socket.h>])
AC_CHECK_TYPES([struct ucred],[],[],[#include <sys/socket.h>])
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
AC_CHECK_FUNCS([bzero])
AC_CHECK_FUNCS([dup2])
AC_CHECK_FUNCS([endgrent])
AC_CHECK_FUNCS([endpwent])
AC_CHECK_FUNCS([ftruncate])
AC_CHECK_FUNCS([gethostbyaddr])
AC_CHECK_FUNCS([strrchr])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([select])
AC_CHECK_FUNCS([setgrent])
AC_CHECK_FUNCS([setgroupent])
AC_CHECK_FUNCS([setpassent])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([vasprintf])
AC_CHECK_FUNCS([getprogname],[],[AC_LIBOBJ(progname)])
AC_CHECK_FUNCS([pidfile_open pidfile_remove pidfile_write],[],[AC_LIBOBJ(pidfile)])
AC_REPLACE_FUNCS([closefrom flopen strlcat strlcpy])

AC_OUTPUT(Makefile)

