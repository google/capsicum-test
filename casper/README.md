Casper
======

Casper is a system daemon that provides services to Capsicum-sandboxed applications.  These applications need to open a
connection to Casper before performing `cap_enter()`, and then use the connection to proxy out particular operations that
are not possible within the capability mode sandbox.

In particular, the Casper sub-daemons provide access to:

 - DNS name/address resolution (`libcapsicum_dns.h`)
 - Password database interrogation (`libcapsicum_pwd.h`)
 - Group database interrogation (`libcapsicum_grp.h`)
 - Random number generation using system facililities (`libcapsicum_random.h`)
 - Sysctl operations (FreeBSD-only, `libcapsicum_sysctl.h`)


Installation
------------

To install Casper from a bare source code repository, run `autoreconf -iv` (which runs:

    % libtoolize              # generates m4/*, ltmain.sh
    % aclocal                 # generates aclocal.m4
    % autoconf                # generates configure
    % autoheader              # generates config.h.in
    % automake --add-missing  # generates Makefile.in, scripts

in preparation for a build.)

From a tarball (created from `make dist-gzip`) run:

    % ./configure             # generates Makefile, config.h
    % make
    % make install

To generate Debian packages use:

    % dpkg-buildpackage  -us -uc


Process Structure
-----------------

The `casperd` daemon runs at system start-of-day, and forks itself to run as two distinct processes (albeit running the
same executable), `casper` and `zygote`.  The `casper` process accepts connections from user applications, but when an
application requests a specific service it forwards the service open request to the `zygote` process, which launches a
new sub-daemon process of the appropriate type.  This sub-daemon runs a new executable (described by the configuration
files for Casper, typically held in `/etc/casper`) which is specific to this particular application, and which
terminates when the application closes the service connection.


Source Code Layout
------------------

The Casper source code is divided into the following subdirectories, analogously to the FreeBSD source layout.

 - `src/libnv/`: Holds the libnv serialization library source code.  This library is used for serialization throughout
   Casper; unlike other serialization/RPC libraries, `libnv` allows file descriptors to be passed between processes.
 - `src/libpjdlog/`: Logging library.
 - `src/libcapsicum/`: Library to allow applications to access Casper functionality.
 - `src/libcasper/`: Library holding common code used by the main `casperd` daemon and the various sub-daemons.
 - `src/casperd/`: Main Casper daemon source code.
 - `src/casper/`: Sub-daemon source code, held in individual subdirectories.
    - `src/casper/dns/`: DNS sub-daemon source code.
    - `src/casper/pwd/`: Password sub-daemon source code.
    - `src/casper/grp/`: Group sub-daemon source code.
    - `src/casper/random/`: Random sub-daemon source code.
    - `src/casper/sysctl/`: Sysctl sub-daemon source code.

User applications need access to the public parts of `libnv` (for serializing their requests) and `libcapsicum`.


Installed Layout
----------------

The following items are part of a Casper installation:

 - Executables:
    - `casperd`: Main Casper daemon
    - `casperd.dns`: Casper DNS sub-daemon
    - `casperd.pwd`: Casper password sub-daemon
    - `casperd.grp`: Casper group sub-daemon
    - `casperd.random`: Casper random sub-daemon
    - `casperd.sysctl`: Casper sysctl sub-daemon
 - Libraries:
    - `libcapsicum`: Access to Casper functions
    - `libnv`: Serialization/RPC library used by Casper
 - Ancillary Files
    - `/var/run/casperd.pid`: PID file controlling single instance of `casperd` daemon.
    - `/etc/casper/`: Directory holding service configuration files.  Each file has the same name as the service, and
      holds the path to the sub-daemon that implements that service.
        - `/etc/casper/service.dns`: File holding name of DNS sub-daemon executable.
        - `/etc/casper/service.pwd`: File holding name of password sub-daemon executable.
        - `/etc/casper/service.grp`: File holding name of group sub-daemon executable.
        - `/etc/casper/service.random`: File holding name of random sub-daemon executable.
        - `/etc/casper/service.sysctl`: File holding name of sysctl sub-daemon executable.
    - `/var/run/casper`: UNIX domain socket.  The default value for this can be overridden with the `-S sockpath`
      command line option.

The default locations of the ancillary files can be overridden with the `casperd` command-line options:

 - `-P pidfile`: Override PID file location
 - `-D confdir`: Override service configuration directory location.
 - `-S sockfile`: Override UNIX socket location.
 - `-F`: Run `casperd` in the foreground, without daemonizing.
 - `-v`: Increase logging verbosity (can be repeated).


Testing
-------

The `make check` target runs the `test-wrapper-sh` script, which:

 - starts a non-daemonized instance of `casperd`, configured to run entirely locally
 - runs the tests from the `tests/` subdirectory via the `casper-test` binary
 - terminates the local `casperd` daemon.
