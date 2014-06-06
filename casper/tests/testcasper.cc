#include <libcapsicum.h>

#include "gtest/gtest.h"

extern const char *casper_sock;

TEST(Casper, Init) {
  cap_channel_t *chan = cap_init_sock(casper_sock);
  if (!chan) {
    fprintf(stderr, "Skipping test as cap_init_sock('%s') failed\n", casper_sock);
    return;
  }
  EXPECT_NE(nullptr, chan);
  cap_close(chan);
}

TEST(Casper, InitFail) {
  cap_channel_t *chan = cap_init_sock("bogus");
  EXPECT_EQ(nullptr, chan);
}
