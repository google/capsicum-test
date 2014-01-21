// Tests for POSIX message queue functionality.

#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

#include <string>

#include "capsicum.h"
#include "syscalls.h"
#include "capsicum-test.h"

// Run a test case in a forked process, possibly cleaning up a
// message after completion
#define FORK_TEST_ON_MQ(test_case_name, test_name, test_mq)    \
    static void test_case_name##_##test_name##_ForkTest();     \
    TEST(test_case_name, test_name ## Forked) {                \
      _RUN_FORKED(test_case_name##_##test_name##_ForkTest,     \
                  #test_case_name, #test_name);                \
      const char *mqname = test_mq;                            \
      if (mqname) mq_unlink_(mqname);                          \
    }                                                          \
    static void test_case_name##_##test_name##_ForkTest()

static bool invoked;
void seen_it_done_it(int v) {
  invoked = true;
}

FORK_TEST_ON_MQ(PosixMqueue, CapMode, "/cap_mq") {
  int mq = mq_open_("/cap_mq", O_RDWR|O_CREAT, 0644, NULL);
  EXPECT_OK(mq);
  // On FreeBSD, turn on message queue support with:
  //  - 'kldload mqueuefs'
  //  -  'options P1003_1B_MQUEUE' in kernel build config.
  if (mq < 0) return;
  int cap_read_mq = cap_new(mq, CAP_READ);
  int cap_write_mq = cap_new(mq, CAP_WRITE);
  int cap_poll_mq = cap_new(mq, CAP_POLL_EVENT);
  EXPECT_OK(mq_close_(mq));

  signal(SIGUSR2, seen_it_done_it);

#ifndef __FreeBSD__
  // TODO(drysdale): figure out why POSIX message queues get -ECAPMODE on FreeBSD.
  EXPECT_OK(cap_enter());  // Enter capability mode

  // Can no longer access the message queue via the POSIX IPC namespace.
  EXPECT_CAPMODE(mq_open_("/cap_mw", O_RDWR|O_CREAT, 0644, NULL));
#endif

  struct sigevent se;
  se.sigev_notify = SIGEV_SIGNAL;
  se.sigev_signo = SIGUSR2;
  EXPECT_OK(mq_notify_(cap_poll_mq, &se));
  EXPECT_NOTCAPABLE(mq_notify_(cap_read_mq, &se));
  EXPECT_NOTCAPABLE(mq_notify_(cap_write_mq, &se));

  const unsigned int kPriority = 10;
  const char* message = "xyzzy";
  struct timespec ts;
  ts.tv_sec = 1;
  ts.tv_nsec = 0;
  EXPECT_OK(mq_timedsend_(cap_write_mq, message, strlen(message) + 1, kPriority, &ts));
  EXPECT_NOTCAPABLE(mq_timedsend_(cap_read_mq, message, strlen(message) + 1, kPriority, &ts));

  sleep(1);  // Give the notification a chance to arrive.
  EXPECT_TRUE(invoked);

  struct mq_attr mqa;
  EXPECT_OK(mq_getattr_(cap_poll_mq, &mqa));
  EXPECT_OK(mq_setattr_(cap_poll_mq, &mqa, NULL));
  EXPECT_NOTCAPABLE(mq_getattr_(cap_write_mq, &mqa));

  char* buffer = (char *)malloc(mqa.mq_msgsize);
  unsigned int priority;
  EXPECT_NOTCAPABLE(mq_timedreceive_(cap_write_mq, buffer, mqa.mq_msgsize, &priority, &ts));
  EXPECT_OK(mq_timedreceive_(cap_read_mq, buffer, mqa.mq_msgsize, &priority, &ts));
  EXPECT_EQ(std::string(message), std::string(buffer));
  EXPECT_EQ(kPriority, priority);
  free(buffer);

  close(cap_read_mq);
  close(cap_write_mq);
  close(cap_poll_mq);
}
