AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
CFLAGS = --pedantic -Wall -O2 -g -I . -I src

lib_LTLIBRARIES = libnv.la libcapsicum.la
noinst_LIBRARIES = libpjdlog.a libcasper.a libgtest.a
sbin_PROGRAMS = casperd casper.dns casper.grp casper.pwd casper.random # casper.sysctl
noinst_PROGRAMS = casper-test
TESTS = test-wrapper.sh
EXTRA_DIST = test-wrapper.sh etc debian

libnv_la_SOURCES = src/libnv/dnvlist.c src/libnv/msgio.c src/libnv/nvlist.c src/libnv/nvpair.c src/libnv/common_impl.h src/libnv/msgio.h src/libnv/nv_impl.h src/libnv/nvlist_impl.h src/libnv/nvpair_impl.h src/local.h src/sys_endian.h
libnv_la_HEADERS = src/libnv/dnv.h src/libnv/nv.h
libnv_la_CFLAGS = -I src/libnv
libnv_ladir = ${includedir}

libpjdlog_a_SOURCES = src/libpjdlog/pjdlog.c src/libpjdlog/pjdlog.h src/local.h src/sys_endian.h
libpjdlog_a_CFLAGS = -I src/libpjdlog

libcapsicum_la_SOURCES = src/libcapsicum/libcapsicum.c src/libcapsicum/libcapsicum_dns.c src/libcapsicum/libcapsicum_grp.c src/libcapsicum/libcapsicum_impl.h src/libcapsicum/libcapsicum_pwd.c src/libcapsicum/libcapsicum_random.c src/libcapsicum/libcapsicum_service.c src/libcapsicum/libcapsicum_sysctl.c src/local.h src/sys_endian.h
libcapsicum_la_HEADERS = src/libcapsicum/libcapsicum.h src/libcapsicum/libcapsicum_dns.h src/libcapsicum/libcapsicum_grp.h src/libcapsicum/libcapsicum_pwd.h src/libcapsicum/libcapsicum_random.h src/libcapsicum/libcapsicum_service.h src/libcapsicum/libcapsicum_sysctl.h
libcapsicum_la_LIBADD = $(LTLIBOBJS) -lnv
libcapsicum_la_CFLAGS = -I src/libnv -I src/libcapsicum
libcapsicum_ladir = ${includedir}

libcasper_a_SOURCES = src/libcasper/libcasper.c src/libcasper/libcasper_impl.h src/libcasper/libcasper.h
libcasper_a_CFLAGS = -I src/libnv -I src/libpjdlog -I src/libcapsicum -I src/libcasper

casperd_SOURCES = src/casperd/casperd.c src/casperd/zygote.c src/casperd/zygote.h src/local.h src/sys_endian.h src/pidfile.h
casperd_LDADD = libcasper.a libcapsicum.la libnv.la libpjdlog.a $(LIBOBJS)
casperd_CFLAGS = -I src/libnv -I src/libpjdlog -I src/libcapsicum -I src/libcasper -I src/casperd

casperdconfdir = ${sysconfdir}/casper
casperdconf_DATA = system.dns system.grp system.pwd system.random
DISTCLEANFILES = system.dns system.grp system.pwd system.random
system.dns:
	echo ${sbindir}/casper.dns > $@
system.grp:
	echo ${sbindir}/casper.grp > $@
system.pwd:
	echo ${sbindir}/casper.pwd > $@
system.random:
	echo ${sbindir}/casper.random > $@

casper_dns_SOURCES = src/casper/dns/dns.c
casper_dns_LDADD = libcasper.a libcapsicum.la libnv.la libpjdlog.a $(LIBOBJS)
casper_dns_CFLAGS = -I src/libnv -I src/libpjdlog -I src/libcapsicum -I src/libcasper -I src/casperd

casper_grp_SOURCES = src/casper/grp/grp.c
casper_grp_LDADD = libcasper.a libcapsicum.la libnv.la libpjdlog.a $(LIBOBJS)
casper_grp_CFLAGS = -I src/libnv -I src/libpjdlog -I src/libcapsicum -I src/libcasper -I src/casperd

casper_pwd_SOURCES = src/casper/pwd/pwd.c
casper_pwd_LDADD = libcasper.a libcapsicum.la libnv.la libpjdlog.a $(LIBOBJS)
casper_pwd_CFLAGS = -I src/libnv -I src/libpjdlog -I src/libcapsicum -I src/libcasper -I src/casperd

casper_random_SOURCES = src/casper/random/random.c
casper_random_LDADD = libcasper.a libcapsicum.la libnv.la libpjdlog.a $(LIBOBJS)
casper_random_CFLAGS = -I src/libnv -I src/libpjdlog -I src/libcapsicum -I src/libcasper -I src/casperd

libgtest_a_SOURCES = gtest-1.6.0/src/gtest-all.cc \
  gtest-1.6.0/src/gtest-death-test.cc \
  gtest-1.6.0/src/gtest-filepath.cc \
  gtest-1.6.0/src/gtest-internal-inl.h \
  gtest-1.6.0/src/gtest-port.cc \
  gtest-1.6.0/src/gtest-printers.cc \
  gtest-1.6.0/src/gtest-test-part.cc \
  gtest-1.6.0/src/gtest-typed-test.cc \
  gtest-1.6.0/src/gtest.cc \
  gtest-1.6.0/include/gtest/gtest-death-test.h \
  gtest-1.6.0/include/gtest/gtest-message.h \
  gtest-1.6.0/include/gtest/gtest-param-test.h \
  gtest-1.6.0/include/gtest/gtest-printers.h \
  gtest-1.6.0/include/gtest/gtest-spi.h \
  gtest-1.6.0/include/gtest/gtest-test-part.h \
  gtest-1.6.0/include/gtest/gtest-typed-test.h \
  gtest-1.6.0/include/gtest/gtest.h \
  gtest-1.6.0/include/gtest/gtest_pred_impl.h \
  gtest-1.6.0/include/gtest/gtest_prod.h \
  gtest-1.6.0/include/gtest/internal/gtest-death-test-internal.h \
  gtest-1.6.0/include/gtest/internal/gtest-filepath.h \
  gtest-1.6.0/include/gtest/internal/gtest-internal.h \
  gtest-1.6.0/include/gtest/internal/gtest-linked_ptr.h \
  gtest-1.6.0/include/gtest/internal/gtest-param-util-generated.h \
  gtest-1.6.0/include/gtest/internal/gtest-param-util.h \
  gtest-1.6.0/include/gtest/internal/gtest-port.h \
  gtest-1.6.0/include/gtest/internal/gtest-string.h \
  gtest-1.6.0/include/gtest/internal/gtest-tuple.h \
  gtest-1.6.0/include/gtest/internal/gtest-type-util.h
libgtest_a_CXXFLAGS = -I gtest-1.6.0/include -I gtest-1.6.0 -DGTEST_USE_OWN_TR1_TUPLE=1 -DGTEST_HAS_TR1_TUPLE=1

casper_test_SOURCES = tests/testnv.cc tests/testmsgio.cc tests/testpjdlog.cc tests/testcasper.cc tests/testdns.cc tests/testgrp.cc tests/testpwd.cc tests/testrandom.cc tests/casper-test-main.cc
casper_test_LDADD  = libcapsicum.la libnv.la libpjdlog.a libgtest.a -lpthread
casper_test_CXXFLAGS = -std=c++11 -Wall -g -I gtest-1.6.0/include -I gtest-1.6.0 -I src/libnv -I src/libpjdlog -I src/libcapsicum -DGTEST_USE_OWN_TR1_TUPLE=1 -DGTEST_HAS_TR1_TUPLE=1

dist_man_MANS = src/libnv/libnv.3 src/libcapsicum/libcapsicum.3
