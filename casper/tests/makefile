all: casper-test
OBJECTS=testnv.o casper-test-main.o

GTEST_DIR=../../gtest-1.6.0
GTEST_INCS=-I$(GTEST_DIR)/include -I$(GTEST_DIR)
GTEST_FLAGS=-DGTEST_USE_OWN_TR1_TUPLE=1 -DGTEST_HAS_TR1_TUPLE=1
CXXFLAGS+=-Wall -g -ansi $(GTEST_INCS) $(GTEST_FLAGS) -I../libnv

casper-test: $(OBJECTS) libgtest.a
	$(CXX) -g -o $@ $(OBJECTS) libgtest.a -lpthread ../libnv/.libs/libnv.a

test: casper-test
	./casper-test
gtest-all.o:
	$(CXX) -I$(GTEST_DIR)/include -I$(GTEST_DIR) $(GTEST_FLAGS) -c ${GTEST_DIR}/src/gtest-all.cc
libgtest.a: gtest-all.o
	$(AR) -rv libgtest.a gtest-all.o

clean:
	rm -rf gtest-all.o libgtest.a casper-test $(OBJECTS)


