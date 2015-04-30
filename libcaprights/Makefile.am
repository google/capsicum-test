AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
CFLAGS = --pedantic -Wall -O2
lib_LTLIBRARIES = libcaprights.la
libcaprights_la_SOURCES = capsicum.c procdesc.c signal.c linux-bpf-capmode.c
libcaprights_la_HEADERS = capsicum.h procdesc.h
libcaprights_ladir = ${includedir}/sys
dist_man_MANS = man/cap_enter.3 man/cap_fcntls_get.3 man/cap_fcntls_limit.3 man/cap_getmode.3 man/cap_ioctls_get.3 man/cap_ioctls_limit.3 man/cap_rights_clear.3 man/cap_rights_contains.3 man/cap_rights_get.3 man/cap_rights_init.3 man/cap_rights_is_set.3 man/cap_rights_is_valid.3 man/cap_rights_limit.3 man/cap_rights_merge.3 man/cap_rights_remove.3 man/cap_rights_set.3
