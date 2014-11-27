#include "config.h"

/* Include the appropriate header file for Capsicum function declarations */
#ifdef HAVE_CAPSICUM_HEADER
# ifdef HAVE_CAPSICUM_SYS_CAPSICUM_H
#  include <sys/capsicum.h>
# else
#  ifdef HAVE_CAPSICUM_SYS_CAPABILITY_H
#   include <sys/capability.h>
#  endif
# endif
#endif

#include <stdio.h>
#include <errno.h>

int main(void)
{
#ifdef HAVE_CAPSICUM
  int rc;
  cap_rights_t rights;
  cap_rights_init(&rights, CAP_WRITE);
  fprintf(stderr, "Compiled with Capsicum support\n");
  rc = cap_rights_limit(2, &rights);
  if (rc < 0) {
    fprintf(stderr, "cap_right_limit() failed, errno=%d\n", errno);
  }
#else
  fprintf(stderr, "Compiled without Capsicum support\n");
#endif
  return 0;
}
