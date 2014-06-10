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
comparative testing across multiple OSes, and then substantially extended.

OS Configuration
----------------

### Linux

The following kernel configuration options are needed to run the tests:

 - `CONFIG_64BIT`: Capsicum support is currently only implemented for 64 bit mode
 - `CONFIG_SECURITY`: enable Linux Security Module (LSM) support
 - `CONFIG_SECURITY_PATH`: enable LSM hooks for path operations
 - `CONFIG_SECURITY_CAPSICUM`: enable the Capsicum framework
 - `CONFIG_PROCDESC`: enable Capsicum process-descriptor functionality
 - `CONFIG_DEBUG_FS`: enable debug filesystem
 - `CONFIG_IP_SCTP`: enable SCTP support

### FreeBSD 9.x

The following kernel configuration options are needed so that all tests can run:

  - `options CAPABILITIES`: Enable capabilities
  - `options CAPABILITY_MODE`: Enable capability mode
  - `options PROCDESC`: Enable process descriptors
  - `options P1003_1B_MQUEUE`: Enable POSIX message queues (or `kldload mqueuefs`)
  - `options VFS_AIO`: Enable asynchronous I/O (or `kldload aio`)

### FreeBSD 10.x

The following kernel configuration options are needed so that all tests can run:

  - `options P1003_1B_MQUEUE`: Enable POSIX message queues (or `kldload mqueuefs`)
  - `options VFS_AIO`: Enable asynchronous I/O (or `kldload aio`)

Other Dependencies
------------------

### Linux

The following additional development packages are needed to build the full test suite on Linux.

 - libcaprights: See below
 - libcap-dev: Provides headers for POSIX.1e capabilities.
 - libsctp1: Provides SCTP library functions.
 - libsctp-dev: Provides headers for SCTP library functions.


Linux libcaprights
------------------

The Capsicum userspace library is held in the libcaprights/ subdirectory.  This library needs to
be built (with "./configure; make" or "dpkg-buildpackage -uc -us") and
installed (with "make install" or "dpkg -i libcaprights*.deb") to allow the tests to
build.
