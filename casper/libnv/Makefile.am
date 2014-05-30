AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
CFLAGS = --pedantic -Wall -O2
lib_LTLIBRARIES = libnv.la
libnv_la_SOURCES = dnvlist.c msgio.c nvlist.c nvpair.c common_impl.h config.h nv_impl.h nvlist_impl.h nvpair_impl.h sys_endian.h
libnv_la_HEADERS = dnv.h nv.h msgio.h
libnv_ladir = ${includedir}
dist_man_MANS = libnv.3
