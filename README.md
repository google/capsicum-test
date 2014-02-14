Capsicum User Space Tests
=========================

This directory holds unit tests for [Capsicum](http://www.cl.cam.ac.uk/research/security/capsicum/)
object-capabilities. The tests exercise the syscall interface to a Capsicum-enabled operating system,
currently either [FreeBSD 9.x](http://www.freebsd.org) or a modified Linux kernel (the
[capsicum-linux](http://github.com/google/capsicum-linux) project).

The tests are written in C++98, and use the [Google Test](https://code.google.com/p/googletest/)
framework, with some additions to fork off particular tests (because a process that enters capability
mode cannot leave it again).

Provenance
----------

The original basis for these tests was:

 - [unit tests](https://github.com/freebsd/freebsd/tree/master/tools/regression/security/cap_test)
   written by Robert Watson and Jonathan Anderson for the original FreeBSD 9.x Capsicum implementation
 - [unit tests](http://git.chromium.org/gitweb/?p=chromiumos/third_party/kernel-capsicum.git;a=tree;f=tools/testing/capsicum_tests;hb=refs/heads/capsicum) written by Meredydd Luff for the original Capsicum-Linux port.

These tests were coalesced and moved into an independent repository to enable
comparative testing across multiple OSes.

OS Configuration
----------------

### FreeBSD 9.x

The following kernel configuration options are needed so that all tests can run:

  - `options CAPABILITIES`: Enable capabilities
  - `options CAPABILITY_MODE`: Enable capability mode
  - `options PROCDESC`: Enable process descriptors
  - `options P1003_1B_MQUEUE`: Enable POSIX message queues (or `kldload mqueuefs`)
  - `options VFS_AIO`: Enable asynchronous I/O (or `kldload aio`)

### Linux

The following kernel configuration options are needed to run the tests:

 - `CONFIG_64BIT`: Capsicum support is currently only implemented for 64 bit mode
 - `CONFIG_SECURITY`: enable Linux Security Module (LSM) support
 - `CONFIG_SECURITY_PATH`: enable LSM hooks for path operations
 - `CONFIG_SECURITY_CAPSICUM`: enable the Capsicum LSM
 - `CONFIG_PROCDESC`: enable Capsicum process-descriptor functionality
 - `CONFIG_DEBUG_FS`: enable debug filesystem

Also, the headers for POSIX.1e capabilities are needed to build the Linux version
of the tests.  On Debian systems this is typically provided by the libcap-deb
package.
