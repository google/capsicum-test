OS:=$(shell uname)
ifeq ($(OS),Linux)
LIBSCTP=-lsctp
ifeq ($(wildcard /usr/lib/libcapsicum.a),)
LIBCAPSICUM=/usr/lib/x86_64-linux-gnu/libcapsicum.a
else
LIBCAPSICUM=/usr/lib/libcapsicum.a
endif
endif
include makefile
