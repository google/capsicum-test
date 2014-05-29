OS:=$(shell uname)
ifeq ($(OS),Linux)
LIBSCTP=-lsctp
ifeq ($(wildcard /usr/lib/libcaprights.a),)
LIBCAPRIGHTS=/usr/lib/x86_64-linux-gnu/libcaprights.a
else
LIBCAPRIGHTS=/usr/lib/libcaprights.a
endif
endif
include makefile
