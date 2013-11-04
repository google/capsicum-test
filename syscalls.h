/*
 * Minimal portability layer for system call differences between
 * Capsicum OSes.
 */
#ifndef __SYSCALLS_H__
#define __SYSCALLS_H__

/************************************************************
 * FreeBSD
 ************************************************************/
#ifdef __FreeBSD__

/* Map umount2 (Linux) syscall to unmount (FreeBSD) syscall */
#define umount2(T, F) unmount(T, F)

/* Map sighandler_y (Linux) to sig_t (FreeBSD) */
#define sighandler_t sig_t

/* profil(2) has a first argument of char* */
#define profil_arg1_t char

/* FreeBSD has getdents(2) available */
#include <sys/types.h>
#include <dirent.h>
inline int getdents_(unsigned int fd, void *dirp, unsigned int count) {
  return getdents(fd, (char*)dirp, count);
}
#include <sys/mman.h>
inline int mincore_(void *addr, size_t length, unsigned char *vec) {
  return mincore(addr, length, (char*)vec);
}

/* Map Linux-style sendfile to FreeBSD sendfile */
#include <sys/socket.h>
#include <sys/uio.h>
inline ssize_t sendfile_(int out_fd, int in_fd, off_t *offset, size_t count) {
  return sendfile(in_fd, out_fd, *offset, count, NULL, offset, 0);
}

/* Features available */
#define HAVE_CHFLAGS
#define HAVE_GETFSSTAT
#define HAVE_REVOKE
#define HAVE_GETLOGIN
#define HAVE_SYSARCH
#include <machine/sysarch.h>
#define HAVE_STAT_BIRTHTIME
#define HAVE_SYSCTL
#define HAVE_FPATHCONF

/* FreeBSD only allows root to call mlock[all]/munlock[all] */
#define MLOCK_REQUIRES_ROOT 1
/* FreeBSD effectively only allows root to call sched_setscheduler */
#define SCHED_SETSCHEDULER_REQUIRES_ROOT 1

#endif

/************************************************************
 * Linux
 ************************************************************/
#ifdef __linux__
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/sendfile.h>

/* profil(2) has a first argument of unsigned short* */
#define profil_arg1_t unsigned short

inline int getdents_(unsigned int fd, void *dirp, unsigned int count) {
  return syscall(__NR_getdents, fd, dirp, count);
}
#define mincore_ mincore
#define sendfile_ sendfile

#define HAVE_DUP3
#define HAVE_PIPE2
#include <sys/fsuid.h>  /* for setfsgid()/setfsuid() */
#define HAVE_SETFSUID
#define HAVE_SETFSGID
#define HAVE_READAHEAD
#define HAVE_SEND_RECV_MMSG
#define HAVE_SYNCFS
#define HAVE_SYNC_FILE_RANGE
#include <sys/uio.h>  /* for vmsplice */
#define HAVE_VMSPLICE

/* Linux allows anyone to call mlock[all]/munlock[all] */
#define MLOCK_REQUIRES_ROOT 0
/* Linux allows anyone to call sched_setscheduler */
#define SCHED_SETSCHEDULER_REQUIRES_ROOT 1

#endif

#endif /*__SYSCALLS_H__*/
