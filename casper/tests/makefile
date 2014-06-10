# This makefile relies on libnv & libcapsicum being installed, and assumes
# that casperd is running live on the current system.  To run tests locally,
# use the 'make check' target in the director above this (which also runs
# tests that rely on internal headers).
all: casper-test

# Note: testpjdlog.o, testmsgio.o not included as they are Casper-internal
OBJECTS=testnv.o testcasper.o testdns.o testgrp.o testpwd.o testrandom.o casper-test-main.o

GTEST_DIR=../gtest-1.6.0
GTEST_INCS=-I$(GTEST_DIR)/include -I$(GTEST_DIR)
GTEST_FLAGS=-DGTEST_USE_OWN_TR1_TUPLE=1 -DGTEST_HAS_TR1_TUPLE=1
CXXFLAGS+=-Wall -g -std=c++11 $(GTEST_INCS) $(GTEST_FLAGS)

casper-test: $(OBJECTS) libgtest.a
	$(CXX) -g -o $@ $(OBJECTS) libgtest.a -lcapsicum -lnv -lpthread
test: casper-test
	./casper-test
gtest-all.o:
	$(CXX) -I$(GTEST_DIR)/include -I$(GTEST_DIR) $(GTEST_FLAGS) -c ${GTEST_DIR}/src/gtest-all.cc
libgtest.a: gtest-all.o
	$(AR) -rv libgtest.a gtest-all.o

clean:
	rm -rf gtest-all.o libgtest.a casper-test $(OBJECTS)


