all: capsicum-test smoketest mini-me mini-me.noexec
OBJECTS=capsicum-test-main.o capsicum-test.o capability-fd.o fexecve.o procdesc.o capmode.o fcntl.o ioctl.o openat.o sysctl.o select.o mqueue.o socket.o sctp.o capability-fd-pair.o linux.o

GTEST_DIR=gtest-1.6.0
GTEST_INCS=-I$(GTEST_DIR)/include -I$(GTEST_DIR)
GTEST_FLAGS=-DGTEST_USE_OWN_TR1_TUPLE=1 -DGTEST_HAS_TR1_TUPLE=1
CXXFLAGS+=-Wall -g -ansi $(GTEST_INCS) $(GTEST_FLAGS)

capsicum-test: $(OBJECTS) libgtest.a
	$(CXX) -g -o $@ $(OBJECTS) libgtest.a -lpthread -lrt $(LIBSCTP) $(LIBCAPRIGHTS)

# Small statically-linked program for fexecve tests
# (needs to be statically linked so that execve()ing it
# doesn't involve ld.so traversing the filesystem).
mini-me: mini-me.c
	$(CC) -static -o $@ $<
mini-me.noexec: mini-me
	cp mini-me $@ && chmod -x $@

# Simple C test of Capsicum syscalls
SMOKETEST_OBJECTS=smoketest.o linux-bpf-capmode.o
smoketest: $(SMOKETEST_OBJECTS)
	$(CC) -g -o $@ $(SMOKETEST_OBJECTS) $(LIBCAPRIGHTS)

test: capsicum-test mini-me mini-me.noexec
	./capsicum-test
gtest-all.o:
	$(CXX) -I$(GTEST_DIR)/include -I$(GTEST_DIR) $(GTEST_FLAGS) -c ${GTEST_DIR}/src/gtest-all.cc
libgtest.a: gtest-all.o
	$(AR) -rv libgtest.a gtest-all.o

clean:
	rm -rf gtest-all.o libgtest.a capsicum-test mini-me mini-me.noexec smoketest $(SMOKETEST_OBJECTS) $(OBJECTS)
