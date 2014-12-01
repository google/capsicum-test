# SYNOPSIS
#
#   AX_TYPE_CAP_IOCTL_T
#
# DESCRIPTION
#
#   Check whether <sys/capsicum.h> defines type cap_ioctl_t; defines
#   it to be unsigned long if not defined.
#    - FreeBSD uses unsigned long for ioctl(2), but does not typedef
#      cap_ioctl_t on versions 10.x.
#    - Linux uses unsigned int for ioctl(2), but does have a typedef
#      for cap_ioctl_t.
#
# LICENSE
#
# TODO(drysdale): sort license

AU_ALIAS([TYPE_CAP_IOCTL_T], [AX_TYPE_CAP_IOCTL_T])
AC_DEFUN([AX_TYPE_CAP_IOCTL_T],
[AC_CACHE_CHECK([for cap_ioctl_t], ac_cv_ax_type_cap_ioctl_t,
[
  AC_TRY_COMPILE(
  [#include <sys/capsicum.h>],
  [cap_ioctl_t val = 42; return 0;],
  ac_cv_ax_type_cap_ioctl_t=yes,
  ac_cv_ax_type_cap_ioctl_t=no)
])
  if test $ac_cv_ax_type_cap_ioctl_t != yes; then
    AC_DEFINE(cap_ioctl_t, unsigned long, [Substitute for cap_ioctl_t])
  fi
])

