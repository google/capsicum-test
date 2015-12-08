#include <stdarg.h>
#include <sys/prctl.h>

void setproctitle(const char *fmt, ...)
{
  char buffer[16 + 1];
  va_list ap;

  if (!fmt)
    return

  va_start(ap, fmt);
  buf[16] = '\0';
  (void) vsnprintf(buf, 16, fmt, ap);
  va_end(ap);

  prctl(PR_SET_NAME, buffer, 0, 0, 0);
}

