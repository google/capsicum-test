AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
CFLAGS = --pedantic -Wall -O2 -g -I .
# -I libnv -I libpjdlog -I libcapsicum -I libcasper

lib_LTLIBRARIES = libnv.la libcapsicum.la
noinst_LIBRARIES = libpjdlog.a libcasper.a
bin_PROGRAMS = casperdaemon  # rename this

libnv_la_SOURCES = libnv/dnvlist.c libnv/msgio.c libnv/nvlist.c libnv/nvpair.c libnv/common_impl.h libnv/config.h libnv/msgio.h libnv/nv_impl.h libnv/nvlist_impl.h libnv/nvpair_impl.h libnv/sys_endian.h
libnv_la_HEADERS = libnv/dnv.h libnv/nv.h
libnv_la_CFLAGS = -I libnv
libnv_ladir = ${includedir}

libpjdlog_a_SOURCES = libpjdlog/pjdlog.c libpjdlog/pjdlog.h
libpjdlog_a_CFLAGS = -I libpjdlog

libcapsicum_la_SOURCES = libcapsicum/libcapsicum.c libcapsicum/libcapsicum_dns.c libcapsicum/libcapsicum_dns.h libcapsicum/libcapsicum_grp.c libcapsicum/libcapsicum_grp.h libcapsicum/libcapsicum_impl.h libcapsicum/libcapsicum_pwd.c libcapsicum/libcapsicum_pwd.h libcapsicum/libcapsicum_random.c libcapsicum/libcapsicum_random.h libcapsicum/libcapsicum_service.c libcapsicum/libcapsicum_service.h libcapsicum/libcapsicum_sysctl.c libcapsicum/libcapsicum_sysctl.h
libcapsicum_la_HEADERS = libcapsicum/libcapsicum.h
libcapsicum_la_CFLAGS = -I libnv -I libcapsicum
libcapsicum_ladir = ${includedir}

libcasper_a_SOURCES = libcasper/libcasper.c libcasper/libcasper_impl.h libcasper/libcasper.h
libcasper_a_CFLAGS = -I libnv -I libpjdlog -I libcapsicum -I libcasper

casperdaemon_SOURCES = casperd/casperd.c casperd/zygote.c casperd/zygote.h
casperdaemon_LDADD = libpjdlog.a libcasper.a libcapsicum.la libnv.la
casperdaemon_CFLAGS = -I libnv -I libpjdlog -I libcapsicum -I libcasper -I casperd

dist_man_MANS = libnv/libnv.3 libcapsicum/libcapsicum.3
