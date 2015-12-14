#ifndef TEST_H
#define TEST_H

static int ntest = 1;
static int failures = 0;
static int successes = 0;

#define CHECK(expr)     do {						\
	if ((expr)) {							\
		printf("ok %d %s:%u\n", ntest, __FILE__, __LINE__);	\
		successes++;						\
	} else {							\
		printf("not ok %d %s:%u\n", ntest, __FILE__, __LINE__);	\
		failures++;						\
	}								\
	ntest++;							\
} while (0)
#define CHECKX(expr)     do {						\
	if ((expr)) {							\
		printf("ok %d %s:%u\n", ntest, __FILE__, __LINE__);	\
		successes++;						\
	} else {							\
		printf("not ok %d %s:%u\n", ntest, __FILE__, __LINE__);	\
		exit(1);						\
	}								\
	ntest++;							\
} while (0)

#endif
