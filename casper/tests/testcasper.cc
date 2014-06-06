#include <libcapsicum.h>

#include "gtest/gtest.h"

extern const char *casper_sock;

TEST(Casper, Init) {
  cap_channel_t *chan = cap_init_sock(casper_sock);
  //@@ EXPECT_NE((cap_channel_t *)NULL, chan);
  if (chan) cap_close(chan);
}
