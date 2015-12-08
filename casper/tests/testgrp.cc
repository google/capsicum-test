#include <sys/types.h>
#include <grp.h>

#include <libcasper.h>
#include <cap_grp/cap_grp.h>

#include <string>
#include <map>

#include "gtest/gtest.h"

extern bool verbose;

class CasperGrpTest : public ::testing::Test {
 public:
  CasperGrpTest() : grp_chan_(nullptr), lowest_gid_(-1) {
    cap_channel_t *chan = cap_init();
    EXPECT_NE(nullptr, chan) << "Failed to cap_init()";
    if (!chan) return;
    grp_chan_ = cap_service_open(chan, "system.grp");
    EXPECT_NE(nullptr, grp_chan_) << "Failed to open system.grp service";
    cap_close(chan);

    // Build a local copy of the groups.
    setgrent();
    for (struct group *grp = getgrent(); grp != NULL; grp = getgrent()) {
      groups_[grp->gr_gid] = std::string(grp->gr_name);
      if ((int)grp->gr_gid < lowest_gid_)
        lowest_gid_ = grp->gr_gid;
    }
    endgrent();
  }
  bool CheckSkip() {
    if (grp_chan_ == nullptr) {
      fprintf(stderr, "Skipping test as system.grp service unavailable\n");
      return true;
    } else {
      return false;
    }
  }
  ~CasperGrpTest() {
    if (grp_chan_) cap_close(grp_chan_);
  }
 protected:
  cap_channel_t *grp_chan_;
  std::map<int, std::string> groups_;
  int lowest_gid_;
};

static void print_group(const struct group *grp) {
  if (!grp) return;
  fprintf(stderr, "%d: %s, %s\n", grp->gr_gid,
          grp->gr_name ? grp->gr_name : "<null>",
          grp->gr_passwd ? grp->gr_passwd : "<null>");
}

TEST_F(CasperGrpTest, GetGrent) {
  cap_setgrent(grp_chan_);
  for (struct group *grp = cap_getgrent(grp_chan_); grp != NULL; grp = cap_getgrent(grp_chan_)) {
    if (verbose) print_group(grp);
    const auto it = groups_.find(grp->gr_gid);
    EXPECT_NE(groups_.end(), it);
    if (it != groups_.end()) {
      EXPECT_EQ(it->second, std::string(grp->gr_name));
    }
  }
  cap_endgrent(grp_chan_);
}

TEST_F(CasperGrpTest, GetGrNam) {
  if (CheckSkip()) return;
  if (lowest_gid_ < 0) return;

  struct group sgrp;
  char buffer[1024];
  struct group *grp;

  int rc = cap_getgrnam_r(grp_chan_, groups_[lowest_gid_].c_str(), &sgrp,  buffer, sizeof(buffer), &grp);
  EXPECT_EQ(0, rc);
  EXPECT_NE(nullptr, grp);
  EXPECT_EQ(groups_[lowest_gid_], std::string(grp->gr_name));
  EXPECT_EQ(lowest_gid_, (int)grp->gr_gid);
}

TEST_F(CasperGrpTest, GetGrGid) {
  if (CheckSkip()) return;
  if (lowest_gid_ < 0) return;

  struct group sgrp;
  char buffer[1024];
  struct group *grp;

  int rc = cap_getgrgid_r(grp_chan_, lowest_gid_, &sgrp,  buffer, sizeof(buffer), &grp);
  EXPECT_EQ(0, rc);
  EXPECT_NE(nullptr, grp);
  EXPECT_EQ(groups_[lowest_gid_], std::string(grp->gr_name));
  EXPECT_EQ(lowest_gid_, (int)grp->gr_gid);
}
