all: capsicum-test
OBJECTS=capsicum-test-main.o capability-fd.o fexecve.o procdesc.o capmode.o

GTEST_DIR=gtest-1.6.0
GTEST_INCS=-I$(GTEST_DIR)/include -I$(GTEST_DIR)
CXXFLAGS+=-g $(GTEST_INCS)

capsicum-test: $(OBJECTS) libgtest.a
	$(CXX) -g -o $@ $(OBJECTS) libgtest.a -lpthread

# Small statically-linked program for fexecve tests
# (needs to be statically linked so that execve()ing it
# doesn't involve ld.so traversing the filesystem).
mini-me: mini-me.c
	$(CC) -static -o $@ $<
mini-me.noexec: mini-me
	cp mini-me $@ && chmod -x $@

test: capsicum-test mini-me mini-me.noexec
	./capsicum-test
gtest-all.o:
	$(CXX) -I$(GTEST_DIR)/include -I$(GTEST_DIR) -c ${GTEST_DIR}/src/gtest-all.cc
libgtest.a: gtest-all.o
	$(AR) -rv libgtest.a gtest-all.o

clean:
	rm -rf gtest-all.o libgtest.a capsicum-test mini-me mini-me.noexec $(OBJECTS)
