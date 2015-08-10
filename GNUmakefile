OS:=$(shell uname)

# Set ARCH to 32 or x32 for i386/x32 ABIs
ARCH?=64
ARCHFLAG=-m$(ARCH)

ifeq ($(OS),Linux)
PROCESSOR:=$(shell uname -p)
# PLATFORM_LIBDIR=lib/$(PROCESSOR)-linux-gnu
PLATFORM_LIBDIR?=$(shell gcc -v 2>&1 | grep "Configured with:" | perl -pe 's/.*--libdir=\/usr\/([^\s]+).*/\1/g')

# Override for explicitly specified ARCHFLAG.
# Use locally compiled libcaprights in this case, on the
# assumption that any installed version is 64-bit.
ifeq ($(ARCHFLAG),-m32)
PROCESSOR=i386
PLATFORM_LIBDIR=lib/i386-linux-gnu
LIBCAPRIGHTS=./libcaprights.a
endif
ifeq ($(ARCHFLAG),-mx32)
PROCESSOR=x32
PLATFORM_LIBDIR=libx32
LIBCAPRIGHTS=./libcaprights.a
endif

# Detect presence of libsctp in normal Debian location
ifeq ($(wildcard /usr/$(PLATFORM_LIBDIR)/libsctp.a),)
else
LIBSCTP=-lsctp
CXXFLAGS=-DHAVE_SCTP
endif

ifneq ($(LIBCAPRIGHTS),)
# Build local libcaprights.a (assuming ./configure
# has already been done in libcaprights/)
LOCAL_LIBS=$(LIBCAPRIGHTS)
LIBCAPRIGHTS_OBJS=libcaprights/capsicum.o libcaprights/linux-bpf-capmode.o libcaprights/procdesc.o libcaprights/signal.o
LOCAL_CLEAN=$(LOCAL_LIBS) $(LIBCAPRIGHTS_OBJS)
else
# Detect installed libcaprights static library.
ifneq ($(wildcard /usr/$(PLATFORM_LIBDIR)/libcaprights.a),)
LIBCAPRIGHTS=/usr/$(PLATFORM_LIBDIR)/libcaprights.a
else
ifneq ($(wildcard /usr/lib/libcaprights.a),)
LIBCAPRIGHTS=/usr/lib/libcaprights.a
endif
endif
endif

endif

# Extra test programs for arch-transition tests
EXTRA_PROGS=mini-me.32 mini-me.x32 mini-me.64

# Chain on to the master makefile
include makefile

./libcaprights.a: $(LIBCAPRIGHTS_OBJS)
	ar cr $@ $^

# Small static programs of known architectures
# These may require additional packages to be installed; for example, for Debian:
#  - libc6-dev-i386 provides 32-bit headers for a 64-bit system
#  - libc6-dev-x32 provides headers for the x32 ABI.
mini-me.32: mini-me.c
	$(CC) $(CFLAGS) -m32 -static -o $@ $<
mini-me.x32: mini-me.c
	$(CC) $(CFLAGS) -mx32 -static -o $@ $<
mini-me.64: mini-me.c
	$(CC) $(CFLAGS) -m64 -static -o $@ $<
