OS:=$(shell uname)

# Set ARCHFLAG to 32 or x32 for i386/x32 ABIs
ARCH=64
ARCHFLAG=-m$(ARCH)

ifeq ($(OS),Linux)
PROCESSOR:=$(shell uname -p)
PLATFORM_LIBDIR=lib/$(PROCESSOR)-linux-gnu

# Override for explicitly specified ARCHFLAG
ifeq ($(ARCHFLAG),-m32)
PROCESSOR=i386
PLATFORM_LIBDIR=lib/i386-linux-gnu
endif
ifeq ($(ARCHFLAG),-mx32)
PROCESSOR=x32
PLATFORM_LIBDIR=libx32
endif

# Detect presence of libsctp in normal Debian location
ifeq ($(wildcard /usr/$(PLATFORM_LIBDIR)/libsctp.a),)
else
LIBSCTP=-lsctp
CXXFLAGS=-DHAVE_SCTP
endif

ifeq ($(wildcard /usr/lib/libcaprights.a),)
LIBCAPRIGHTS=/usr/$(PLATFORM_LIBDIR)/libcaprights.a
else
LIBCAPRIGHTS=/usr/lib/libcaprights.a
endif
endif

include makefile
