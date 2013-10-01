all: test

OBJECTS=capsicum-test-main.o cap_new.o

GTEST_DIR=gtest-1.6.0
GTEST_INCS=-I$(GTEST_DIR)/include -I$(GTEST_DIR)
CXXFLAGS+=-g $(GTEST_INCS)

capsicum-test: $(OBJECTS) libgtest.a
	$(CXX) -g -o $@ $(OBJECTS) libgtest.a -lpthread

test: capsicum-test
	./capsicum-test
gtest-all.o:
	$(CXX) -I$(GTEST_DIR)/include -I$(GTEST_DIR) -c ${GTEST_DIR}/src/gtest-all.cc
libgtest.a: gtest-all.o
	$(AR) -rv libgtest.a gtest-all.o

clean:
	rm -rf gtest-all.o libgtest.a capsicum-test $(OBJECTS)
