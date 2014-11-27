# -*- Autoconf -*-

# CHECK_CAPSICUM_HEADER
# ---------------------
# Determine if the header file for Capsicum functions are available, and indicate which
# header file contains them:
#  - FreeBSD 10.x uses <sys/capability.h>
#  - Linux uses <sys/capability.h> for something different (POSIX.1e capabilities), so..
#  - Linux uses <sys/capsicum.h>
#  - FreeBSD >= 11.x also uses <sys/capsicum.h>
#
# Potentially sets the following definitions:
AC_DEFINE([HAVE_CAPSICUM_SYS_CAPSICUM_H],[],[Capsicum functions declared in <sys/capsicum.h>])
AC_DEFINE([HAVE_CAPSICUM_SYS_CAPABILITY_H],[],[Capsicum functions declared in <sys/capability.h>])
AC_DEFINE([HAVE_CAPSICUM_HEADER],[],[Capsicum header file available])
#
# The directory-library declarations in your source code should look something like the following:
#
#   #ifdef HAVE_CAPSICUM_HEADER
#   # ifdef HAVE_CAPSICUM_SYS_CAPSICUM_H
#   #  include <sys/capsicum.h>
#   # else
#   #  ifdef HAVE_CAPSICUM_SYS_CAPABILITY_H
#   #   include <sys/capability.h>
#   #  endif
#   # endif
#   #endif
#
AC_DEFUN([CHECK_CAPSICUM_HEADER],
[# First check existence of the headers
AC_CHECK_HEADERS([sys/capability.h sys/capsicum.h])
# If <sys/capsicum.h> exists, assume it is the correct header.
if test "x$ac_cv_header_sys_capsicum_h" = "xyes" ; then
   AC_DEFINE([HAVE_CAPSICUM_SYS_CAPSICUM_H])
   AC_DEFINE([HAVE_CAPSICUM_HEADER])
elif test "x$ac_cv_header_sys_capability_h" = "xyes" ; then
   # Just <sys/capability.h>; check it declares cap_rights_limit.
   AC_CHECK_DECL([cap_rights_limit],
                  [AC_DEFINE([HAVE_CAPSICUM_SYS_CAPABILITY_H])
                   AC_DEFINE([HAVE_CAPSICUM_HEADER])],[],
                 [sys/capability.h])
fi])

# CHECK_CAPSICUM_LIB
# ------------------
# Add the library providing Capsicum functions to LIBS, if available.
# Potentially sets the following definition:
AC_DEFINE([HAVE_CAPSICUM],[],[Capsicum library available])
#
AC_DEFUN([CHECK_CAPSICUM_LIB],
[AC_LANG_PUSH([C])
AC_SEARCH_LIBS([cap_rights_limit], [caprights],
               [AC_DEFINE([HAVE_CAPSICUM])],[],[])
AC_LANG_POP([C])])
