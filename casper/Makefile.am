AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
CFLAGS = --pedantic -Wall -O2 -g -I . -I src

lib_LTLIBRARIES = libnv.la libcasper.la
noinst_LIBRARIES = libpjdlog.a libgtest.a
noinst_PROGRAMS = casper-test nvlist_add_test nvlist_exists_test nvlist_free_test nvlist_get_test nvlist_move_test nvlist_send_recv_test test_dns test_grp test_pwd
TESTS = casper-test nvlist_add_test nvlist_exists_test nvlist_free_test nvlist_get_test nvlist_move_test nvlist_send_recv_test test_dns test_grp test_pwd
EXTRA_DIST = debian

libnv_la_SOURCES = src/libnv/dnvlist.c src/libnv/msgio.c src/libnv/nvlist.c src/libnv/nvpair.c src/libnv/common_impl.h src/libnv/msgio.h src/libnv/nv_impl.h src/libnv/nvlist_impl.h src/libnv/nvpair_impl.h src/local.h src/sys_endian.h
libnv_la_HEADERS = src/libnv/dnv.h src/libnv/nv.h
libnv_la_CFLAGS = -I src/libnv
libnv_ladir = ${includedir}

libpjdlog_a_SOURCES = src/libpjdlog/pjdlog.c src/libpjdlog/pjdlog.h src/local.h src/sys_endian.h
libpjdlog_a_CFLAGS = -I src/libpjdlog -I src

libcasper_la_SOURCES = src/libcasper/libcasper_impl.c src/libcasper/libcasper_service.c src/libcasper/libcasper.c src/libcasper/zygote.c src/libcasper/service.c src/services/cap_dns/cap_dns.c src/services/cap_random/cap_random.c src/services/cap_grp/cap_grp.c src/services/cap_pwd/cap_pwd.c src/libcasper/libcasper_impl.h src/libcasper/zygote.h src/libcasper/libcasper_service.h src/sys_endian.h src/local.h
libcasper_la_HEADERS = src/libcasper/libcasper.h src/services/cap_sysctl/cap_sysctl.h src/services/cap_dns/cap_dns.h src/services/cap_random/cap_random.h src/services/cap_grp/cap_grp.h src/services/cap_pwd/cap_pwd.h
libcasper_la_LIBADD = $(LTLIBOBJS) -lnv
libcasper_la_CFLAGS = -I src/libnv -I src/libcasper -I src/libpjdlog
libcasper_ladir = ${includedir}

libgtest_a_SOURCES = gtest-1.6.0/src/gtest-all.cc
libgtest_a_CXXFLAGS = -I gtest-1.6.0/include -I gtest-1.6.0 -DGTEST_USE_OWN_TR1_TUPLE=1 -DGTEST_HAS_TR1_TUPLE=1

casper_test_SOURCES = tests/testnv.cc tests/testmsgio.cc tests/testpjdlog.cc tests/testcasper.cc tests/testdns.cc tests/testgrp.cc tests/testpwd.cc tests/testrandom.cc tests/casper-test-main.cc tests/testcasper.h tests/nv_tests.cc tests/dnv_tests.cc tests/nv_array_tests.cc tests/atf-fake.h
casper_test_LDADD  = libcasper.la libnv.la libpjdlog.a libgtest.a -lpthread
casper_test_CXXFLAGS = -std=c++11 -Wall -g -I gtest-1.6.0/include -I gtest-1.6.0 -I src/libnv -I src/libpjdlog -I src/libcasper -I src/services -DGTEST_USE_OWN_TR1_TUPLE=1 -DGTEST_HAS_TR1_TUPLE=1

test_dns_SOURCES = tests/dns.c
test_dns_LDADD = libcasper.la
test_dns_CFLAGS = -Wall -g -I src/libcasper -I src/services

test_grp_SOURCES = tests/grp.c
test_grp_LDADD = libcasper.la
test_grp_CFLAGS = -Wall -g -I src/libcasper -I src/services

test_pwd_SOURCES = tests/pwd.c
test_pwd_LDADD = libcasper.la
test_pwd_CFLAGS = -Wall -g -I src/libcasper -I src/services

nvlist_add_test_SOURCES = tests/nvlist_add_test.c
nvlist_add_test_LDADD = libnv.la
nvlist_add_test_CFLAGS = -Wall -g -I src/libnv
nvlist_exists_test_SOURCES = tests/nvlist_exists_test.c
nvlist_exists_test_LDADD = libnv.la
nvlist_exists_test_CFLAGS = -Wall -g -I src/libnv
nvlist_free_test_SOURCES = tests/nvlist_free_test.c
nvlist_free_test_LDADD = libnv.la
nvlist_free_test_CFLAGS = -Wall -g -I src/libnv
nvlist_get_test_SOURCES = tests/nvlist_get_test.c
nvlist_get_test_LDADD = libnv.la
nvlist_get_test_CFLAGS = -Wall -g -I src/libnv
nvlist_move_test_SOURCES = tests/nvlist_move_test.c
nvlist_move_test_LDADD = libnv.la
nvlist_move_test_CFLAGS = -Wall -g -I src/libnv
nvlist_send_recv_test_SOURCES = tests/nvlist_send_recv_test.c
nvlist_send_recv_test_LDADD = libnv.la
nvlist_send_recv_test_CFLAGS = -Wall -g -I src/libnv

dist_man_MANS = src/libnv/libnv.3 src/libcasper/libcasper.3
