/*
 * Work around definition clashes for struct timespec:
 * - The <linux/sched.h> header pulls in <linux/resource.h>, which has a
     definition of struct timespec (for the kernel).
 * - The <signal.h> header pulls in <time.h>, which holds the normal userspace
     definition of struct timespec.
 * Therefore we can't include both <linux/sched.h> and <signal.h> in the
 * same translation unit.  We only need the definition of SIGCHLD, so use this
 * separate translation unit to pull it into a global variable.
 */
#include <signal.h>

const int sigchld_num = SIGCHLD;
