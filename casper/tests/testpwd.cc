#include <sys/types.h>
#include <pwd.h>

#include "testcasper.h"
#include <cap_pwd/cap_pwd.h>

#include <string>
#include <map>

class CasperPwdTest : public CasperTest {
 public:
  CasperPwdTest() : CasperTest("system.pwd"), lowest_uid_(-1) {
    // Build a local copy of the passwd database.
    setpwent();
    for (struct passwd *pwd = getpwent(); pwd != NULL; pwd = getpwent()) {
      passwds_[pwd->pw_uid] = std::string(pwd->pw_name);
      if ((int)pwd->pw_uid < lowest_uid_)
        lowest_uid_ = pwd->pw_uid;
    }
    endpwent();
  }
 protected:
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

  cap_setpwent(chan_);
  for (struct passwd *pwd = cap_getpwent(chan_); pwd != NULL; pwd = cap_getpwent(chan_)) {
    if (verbose) print_passwd(pwd);
    const auto it = passwds_.find(pwd->pw_uid);
    EXPECT_NE(passwds_.end(), it);
    if (it != passwds_.end()) {
      EXPECT_EQ(it->second, std::string(pwd->pw_name));
    }
  }
  cap_endpwent(chan_);
}

TEST_F(CasperPwdTest, GetPwNam) {
  if (CheckSkip()) return;
  if (lowest_uid_ < 0) return;

  struct passwd spwd;
  char buffer[1024];
  struct passwd *pwd;

  int rc = cap_getpwnam_r(chan_, passwds_[lowest_uid_].c_str(), &spwd,  buffer, sizeof(buffer), &pwd);
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

  int rc = cap_getpwuid_r(chan_, lowest_uid_, &spwd,  buffer, sizeof(buffer), &pwd);
  EXPECT_EQ(0, rc);
  EXPECT_NE(nullptr, pwd);
  EXPECT_EQ(passwds_[lowest_uid_], std::string(pwd->pw_name));
  EXPECT_EQ(lowest_uid_, (int)pwd->pw_uid);
}

