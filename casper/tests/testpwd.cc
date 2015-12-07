#include <sys/types.h>
#include <pwd.h>

#include <libcapsicum.h>
#include <libcapsicum_service.h>
#include <libcapsicum_pwd.h>

#include <string>
#include <map>

#include "gtest/gtest.h"

extern bool verbose;
extern const char *casper_sock;

class CasperPwdTest : public ::testing::Test {
 public:
  CasperPwdTest() : pwd_chan_(nullptr), lowest_uid_(-1) {
    cap_channel_t *chan = cap_init_sock(casper_sock);
    EXPECT_NE(nullptr, chan) << "Failed to open socket " << casper_sock;
    if (!chan) return;
    pwd_chan_ = cap_service_open(chan, "system.pwd");
    EXPECT_NE(nullptr, pwd_chan_) << "Failed to open system.pwd service";
    cap_close(chan);

    // Build a local copy of the passwd database.
    setpwent();
    for (struct passwd *pwd = getpwent(); pwd != NULL; pwd = getpwent()) {
      passwds_[pwd->pw_uid] = std::string(pwd->pw_name);
      if ((int)pwd->pw_uid < lowest_uid_)
        lowest_uid_ = pwd->pw_uid;
    }
    endpwent();
  }
  bool CheckSkip() {
    if (pwd_chan_ == nullptr) {
      fprintf(stderr, "Skipping test as system.pwd service unavailable\n");
      return true;
    } else {
      return false;
    }
  }
  ~CasperPwdTest() {
    if (pwd_chan_) cap_close(pwd_chan_);
  }
 protected:
  cap_channel_t *pwd_chan_;
  std::map<int, std::string> passwds_;
  int lowest_uid_;
};

static void print_passwd(const struct passwd *pwd) {
  if (!pwd) return;
  fprintf(stderr, "%d (g:%d): %s, %s\n",
          pwd->pw_uid, pwd->pw_gid,
          pwd->pw_name ? pwd->pw_name : "<null>",
          pwd->pw_dir ? pwd->pw_dir : "<null>");
}

TEST_F(CasperPwdTest, GetPwent) {
  if (CheckSkip()) return;

  cap_setpwent(pwd_chan_);
  for (struct passwd *pwd = cap_getpwent(pwd_chan_); pwd != NULL; pwd = cap_getpwent(pwd_chan_)) {
    if (verbose) print_passwd(pwd);
    const auto it = passwds_.find(pwd->pw_uid);
    EXPECT_NE(passwds_.end(), it);
    if (it != passwds_.end()) {
      EXPECT_EQ(it->second, std::string(pwd->pw_name));
    }
  }
  cap_endpwent(pwd_chan_);
}

TEST_F(CasperPwdTest, GetPwNam) {
  if (CheckSkip()) return;
  if (lowest_uid_ < 0) return;

  struct passwd spwd;
  char buffer[1024];
  struct passwd *pwd;

  int rc = cap_getpwnam_r(pwd_chan_, passwds_[lowest_uid_].c_str(), &spwd,  buffer, sizeof(buffer), &pwd);
  EXPECT_EQ(0, rc);
  EXPECT_NE(nullptr, pwd);
  EXPECT_EQ(passwds_[lowest_uid_], std::string(pwd->pw_name));
  EXPECT_EQ(lowest_uid_, (int)pwd->pw_uid);
}

TEST_F(CasperPwdTest, GetGrUid) {
  if (CheckSkip()) return;
  if (lowest_uid_ < 0) return;

  struct passwd spwd;
  char buffer[1024];
  struct passwd *pwd;

  int rc = cap_getpwuid_r(pwd_chan_, lowest_uid_, &spwd,  buffer, sizeof(buffer), &pwd);
  EXPECT_EQ(0, rc);
  EXPECT_NE(nullptr, pwd);
  EXPECT_EQ(passwds_[lowest_uid_], std::string(pwd->pw_name));
  EXPECT_EQ(lowest_uid_, (int)pwd->pw_uid);
}

