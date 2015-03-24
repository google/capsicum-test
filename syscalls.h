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
#define getpid_ getpid

/* Map Linux-style sendfile to FreeBSD sendfile */
#include <sys/socket.h>
#include <sys/uio.h>
inline ssize_t sendfile_(int out_fd, int in_fd, off_t *offset, size_t count) {
  return sendfile(in_fd, out_fd, *offset, count, NULL, offset, 0);
}

/* A sample mount(2) call */
#include <sys/param.h>
#include <sys/mount.h>
inline int bogus_mount_() {
  return mount("procfs", "/not_mounted", 0, NULL);
}

/* Mappings for extended attribute functions */
#include <sys/extattr.h>
inline ssize_t flistxattr_(int fd, char *list, size_t size) {
  return extattr_list_fd(fd, EXTATTR_NAMESPACE_USER, list, size);
}
inline ssize_t fgetxattr_(int fd, const char *name, void *value, size_t size) {
  return extattr_get_fd(fd, EXTATTR_NAMESPACE_USER, name, value, size);
}
inline int fsetxattr_(int fd, const char *name, const void *value, size_t size, int flags) {
  return extattr_set_fd(fd, EXTATTR_NAMESPACE_USER, name, value, size);
}
inline int fremovexattr_(int fd, const char *name) {
  return extattr_delete_fd(fd, EXTATTR_NAMESPACE_USER, name);
}

/* mq_* functions are wrappers in FreeBSD so go through to underlying syscalls */
#include <sys/syscall.h>
extern "C" {
extern int __sys_kmq_notify(int, const struct sigevent *);
extern int __sys_kmq_open(const char *, int, mode_t, const struct mq_attr *);
extern int __sys_kmq_setattr(int, const struct mq_attr *__restrict, struct mq_attr *__restrict);
extern ssize_t __sys_kmq_timedreceive(int, char *__restrict, size_t,
                                      unsigned *__restrict, const struct timespec *__restrict);
extern int __sys_kmq_timedsend(int, const char *, size_t, unsigned,
                               const struct timespec *);
extern int  __sys_kmq_unlink(const char *);
}
#define mq_notify_ __sys_kmq_notify
#define mq_open_ __sys_kmq_open
#define mq_setattr_ __sys_kmq_setattr
#define mq_getattr_(A, B) __sys_kmq_setattr(A, NULL, B)
#define mq_timedreceive_ __sys_kmq_timedreceive
#define mq_timedsend_ __sys_kmq_timedsend
#define mq_unlink_ __sys_kmq_unlink
#define mq_close_ close
#include <sys/ptrace.h>
inline long ptrace_(int request, pid_t pid, void *addr, void *data) {
  return ptrace(request, pid, (caddr_t)addr, static_cast<int>((long)data));
}
#define PTRACE_PEEKDATA_ PT_READ_D

/* Features available */
#if __FreeBSD_version >= 1000000
#define HAVE_CHFLAGSAT
#define HAVE_BINDAT
#define HAVE_CONNECTAT
#endif
#define HAVE_CHFLAGS
#define HAVE_GETFSSTAT
#define HAVE_REVOKE
#define HAVE_GETLOGIN
#define HAVE_MKFIFOAT
#define HAVE_SYSARCH
#include <machine/sysarch.h>
#define HAVE_STAT_BIRTHTIME
#define HAVE_SYSCTL
#define HAVE_FPATHCONF
#define HAVE_F_DUP2FD
/* TODO(FreeBSD): re-enable when pselect(2) is allowed in capability mode */
/* #define HAVE_PSELECT */
#define HAVE_SCTP

/* FreeBSD only allows root to call mlock[all]/munlock[all] */
#define MLOCK_REQUIRES_ROOT 1
/* FreeBSD effectively only allows root to call sched_setscheduler */
#define SCHED_SETSCHEDULER_REQUIRES_ROOT 1

#endif  /* FreeBSD */

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
#include <sys/statfs.h>
#include <sys/xattr.h>

/* profil(2) has a first argument of unsigned short* */
#define profil_arg1_t unsigned short

inline int getdents_(unsigned int fd, void *dirp, unsigned int count) {
  return syscall(__NR_getdents, fd, dirp, count);
}
/* A sample mount(2) call */
#include <sys/mount.h>
inline int bogus_mount_() {
  return mount("/dev/bogus", "/bogus", "debugfs", MS_RDONLY, "");
}

#define mincore_ mincore
#define sendfile_ sendfile
/* libc's getpid() wrapper caches the pid value, and doesn't invalidate
 * the cached value on pdfork(), so directly syscall. */
inline pid_t getpid_() {
  return syscall(__NR_getpid);
}
#define flistxattr_ flistxattr
#define fgetxattr_ fgetxattr
#define fsetxattr_ fsetxattr
#define fremovexattr_ fremovexattr
#define mq_notify_ mq_notify
#define mq_open_ mq_open
#define mq_setattr_ mq_setattr
#define mq_getattr_ mq_getattr
#define mq_timedreceive_ mq_timedreceive
#define mq_timedsend_ mq_timedsend
#define mq_unlink_ mq_unlink
#define mq_close_ mq_close
#define ptrace_ ptrace
#define PTRACE_PEEKDATA_ PTRACE_PEEKDATA

/* Features available */
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
#define HAVE_TEE
#define HAVE_SPLICE
#define HAVE_VMSPLICE
#define HAVE_PSELECT
#define HAVE_PPOLL
#define HAVE_EXECVEAT
#define HAVE_SYSCALL

/* Linux allows anyone to call mlock[all]/munlock[all] */
#define MLOCK_REQUIRES_ROOT 0
/* Linux allows anyone to call sched_setscheduler */
#define SCHED_SETSCHEDULER_REQUIRES_ROOT 1

#endif  /* Linux */

#endif /*__SYSCALLS_H__*/
