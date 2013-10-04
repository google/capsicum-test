/*-
 * Copyright (c) 2008-2009 Robert N. M. Watson
 * Copyright (c) 2011 Jonathan Anderson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Test routines to make sure a variety of system calls are or are not
 * available in capability mode.  The goal is not to see if they work, just
 * whether or not they return the expected ECAPMODE.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>

#include "capsicum.h"
#include "capsicum-test.h"

FORK_TEST(Capmode, Syscalls) {
  // Open some files to play with.
  int fd_file = open("/tmp/cap_capmode", O_RDWR|O_CREAT, 0644);
  EXPECT_OK(fd_file);
  int fd_close = open("/dev/null", O_RDWR);
  EXPECT_OK(fd_close);
  int fd_dir = open("/tmp", O_RDONLY);
  EXPECT_OK(fd_dir);
  int fd_socket = socket(PF_INET, SOCK_DGRAM, 0);
  EXPECT_OK(fd_socket);
  int fd_tcp_socket = socket(PF_INET, SOCK_STREAM, 0);
  EXPECT_OK(fd_socket);

  // Enter capability mode.
  EXPECT_OK(cap_enter());

  // System calls that are not permitted in capability mode.
  EXPECT_CAPMODE(access("/tmp/cap_capmode_access", F_OK));
  EXPECT_CAPMODE(acct("/tmp/cap_capmode_acct"));
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = 0;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
#ifndef __linux__
  // TODO(drysdale): reinstate
  EXPECT_CAPMODE(bind(fd_socket, (sockaddr*)&addr, sizeof(addr)));
#endif
  EXPECT_CAPMODE(chdir("/tmp/cap_capmode_chdir"));
#ifdef HAVE_CHFLAGS
  EXPECT_CAPMODE(chflags("/tmp/cap_capmode_chflags", UF_NODUMP));
#endif
  EXPECT_CAPMODE(chmod("/tmp/cap_capmode_chmod", 0644));
  EXPECT_CAPMODE(chown("/tmp/cap_capmode_chown", -1, -1));
  EXPECT_CAPMODE(chroot("/tmp/cap_capmode_chroot"));
#ifndef __linux__
  // TODO(drysdale): check capability before checking other errors?
  // EINVAL, ENETUNREACH currently returned in preference to ECAPMODE
  addr.sin_family = AF_INET;
  addr.sin_port = 53;
  addr.sin_addr.s_addr = htonl(0x08080808);
  EXPECT_CAPMODE(connect(fd_tcp_socket, (sockaddr*)&addr, sizeof(addr)));
#endif
  EXPECT_CAPMODE(creat("/tmp/cap_capmode_creat", 0644));
#ifndef __linux__
  // TODO(drysdale): reinstate
  EXPECT_CAPMODE(fchdir(fd_dir));
#endif
#ifdef HAVE_GETFSSTAT
  struct statfs statfs;
  EXPECT_CAPMODE(getfsstat(&statfs, sizeof(statfs), MNT_NOWAIT));
#endif
  EXPECT_CAPMODE(link("/tmp/foo", "/tmp/bar"));
  struct stat sb;
  EXPECT_CAPMODE(lstat("/tmp/cap_capmode_lstat", &sb));
  EXPECT_CAPMODE(mknod("/tmp/capmode_mknod", 06440, 0));
#ifdef OMIT
  // TODO(drysdale): autoconf away the difference between Linux & FreeBSD mount syscalls
  EXPECT_CAPMODE(mount("procfs", "/not_mounted", 0, NULL));
#endif
  EXPECT_CAPMODE(open("/dev/null", O_RDWR));
  EXPECT_CAPMODE(readlink("/tmp/cap_capmode_readlink", NULL, 0));
#ifdef HAVE_REVOKE
  EXPECT_CAPMODE(revoke("/tmp/cap_capmode_revoke"));
#endif
  EXPECT_CAPMODE(stat("/tmp/cap_capmode_stat", &sb));
  EXPECT_CAPMODE(symlink("/tmp/cap_capmode_symlink_from", "/tmp/cap_capmode_symlink_to"));
  EXPECT_CAPMODE(unlink("/tmp/cap_capmode_unlink"));
  EXPECT_CAPMODE(umount2("/not_mounted", 0));

  // System calls that are permitted in capability mode.
  EXPECT_OK(close(fd_close));
#ifndef __linux__
  // TODO(drysdale): allow dup() in capability mode
  int fd_dup = dup(fd_file);
  EXPECT_OK(fd_dup);
  if (fd_dup >= 0) close(fd_dup);
#endif
  EXPECT_OK(fstat(fd_file, &sb));
  EXPECT_OK(lseek(fd_file, 0, SEEK_SET));
#ifndef __linux__
  // TODO(drysdale): allow msync in capability mode
  EXPECT_OK(msync(&fd_file, 8192, MS_ASYNC));
#endif
  EXPECT_OK(profil(NULL, 0, 0, 0));
  char ch;
  EXPECT_OK(read(fd_file, &ch, sizeof(ch)));
  // recvfrom() either returns -1 with EAGAIN, or 0.
  int rc = recvfrom(fd_socket, NULL, 0, MSG_DONTWAIT, NULL, NULL);
  if (rc < 0) EXPECT_EQ(EAGAIN, errno);
#ifndef __linux__
  // TODO(drysdale): allow setuid in capability mode
  EXPECT_OK(setuid(getuid()));
#endif
  EXPECT_OK(write(fd_file, &ch, sizeof(ch)));

  // These calls will fail for lack of e.g. a proper name to send to,
  // but they are allowed in capability mode, so errno != ECAPMODE.
  EXPECT_FAIL_NOT_CAPMODE(accept(fd_socket, NULL, NULL));
  EXPECT_FAIL_NOT_CAPMODE(getpeername(fd_socket, NULL, NULL));
  EXPECT_FAIL_NOT_CAPMODE(getsockname(fd_socket, NULL, NULL));
#ifdef HAVE_CHFLAGS
  rc = fchflags(fd_file, UF_NODUMP);
  if (rc < 0)  EXPECT_NE(ECAPMODE, errno);
#endif
#ifndef __linux__
  // TODO(drysdale): allow recvmsg/sendmsg in capability mode
  EXPECT_FAIL_NOT_CAPMODE(recvmsg(fd_socket, NULL, 0));
  EXPECT_FAIL_NOT_CAPMODE(sendmsg(fd_socket, NULL, 0));
#endif
  EXPECT_FAIL_NOT_CAPMODE(sendto(fd_socket, NULL, 0, 0, NULL, 0));

  // System calls which should be allowed in capability mode, but which
  // don't return errors, and are thus difficult to check.
  // We will try anyway, by checking errno.
  EXPECT_FAIL_VOID_NOT_CAPMODE(getegid);
  EXPECT_FAIL_VOID_NOT_CAPMODE(geteuid);
  EXPECT_FAIL_VOID_NOT_CAPMODE(getgid);
  EXPECT_FAIL_VOID_NOT_CAPMODE(getpid);
  EXPECT_FAIL_VOID_NOT_CAPMODE(getppid);
  EXPECT_FAIL_VOID_NOT_CAPMODE(getuid);

  // Finally, tests for system calls that don't fit the pattern very well.
#ifndef __linux__
  // TODO(drysdale): allow fork in capability mode
  pid_t pid = fork();
  EXPECT_OK(pid);
  if (pid == 0) {
    // Child: immediately exit.
    exit(0);
  } else if (pid > 0) {
    EXPECT_CAPMODE(waitpid(pid, NULL, 0));
  }
#endif

#ifdef HAVE_GETLOGIN
  EXPECT_TRUE(getlogin() != NULL);
#endif

  // TODO(rnmw): ktrace

#ifndef __linux__
  // TODO(drysdale): allow pipe in capsicum mode
  int fd2[2];
  rc = pipe(fd2);
  EXPECT_EQ(0, rc);
  if (rc == 0) {
    close(fd2[0]);
    close(fd2[1]);
  };
#endif

  // TODO(rnmw): ptrace

#ifdef HAVE_SYSARCH
  // sysarch() is, by definition, architecture-dependent
#if defined (__amd64__) || defined (__i386__)
  long sysarch_arg = 0;
  EXPECT_CAPMODE(sysarch(I386_SET_IOPERM, &sysarch_arg));
#else
  // TOOD(jra): write a test for arm
  FAIL("capmode:no sysarch() test for current architecture");
#endif
#endif

  // TODO(rnmw): No error return from sync(2) to test.
}
