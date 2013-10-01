/*
 * Tests for the process descriptor API for Linux.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#include <uapi/asm-generic/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>

#include <misc/test_harness.h>

#include "procdesc.h"
#include "capsicum.h"

TEST(use_pdfork) {
	int rc, pd = -1;

	rc = pdfork(&pd, 0);
	ASSERT_LE(0, rc);

	if (rc == 0) {
		/* We're the child. */
		ASSERT_EQ(-1, pd);
		exit(0);
	}

	ASSERT_NE(-1, pd);
	close(pd);
}

FIXTURE(pdexit) {
	int pd;
	int pipe;
	int pid;
};

FIXTURE_SETUP(pdexit) {
	int rc;
	int pipes[2];

	rc = pipe(pipes);
	ASSERT_LE(0, rc);
	self->pipe = pipes[1];

	rc = pdfork(&self->pd, 0);
	ASSERT_LE(0, rc);

	if (rc == 0) {
		/* We're the child. */
		read(pipes[0], &rc, sizeof(rc));
		exit(rc);
	} else {
		self->pid = rc;
	}
}

FIXTURE_TEARDOWN(pdexit) {}

/* Can we poll a process descriptor? */
TEST_F(pdexit, poll) {
	struct timeval timeout = {0, 0};
	fd_set fds;
	int rc;
	int pd = self->pd;

	FD_SET(pd, &fds);
	rc = select(pd+1, NULL, NULL, &fds, &timeout);
	EXPECT_EQ(0, rc);

	/* Tell the child to exit. (The value written doesn't matter here.) */
	write(self->pipe, &rc, sizeof(rc));

	FD_SET(pd, &fds);
	rc = select(pd+1, NULL, NULL, &fds, NULL);
	EXPECT_EQ(1, rc);

	close(pd);
}

/* Can multiple processes poll on the same descriptor? */
TEST_F(pdexit, poll_multiple) {
	fd_set fds;
	int rc, other_pid;
	int pd = self->pd;
	struct timeval timeout = {0, 0};

	rc = fork();
	ASSERT_LE(0, rc);
	if (!rc) {
		/* Give the other processes time to get set up, then
		   terminate the child. */
		sleep(1);
		write(self->pipe, &rc, sizeof(rc));
		exit(0);
	}

	other_pid = fork();
	ASSERT_LE(0, other_pid);

	FD_SET(pd, &fds);
	rc = select(pd+1, NULL, NULL, &fds, &timeout);
	EXPECT_EQ(0, rc);

	FD_SET(pd, &fds);
	rc = select(pd+1, NULL, NULL, &fds, NULL);
	EXPECT_EQ(1, rc);

	close(pd);

	if (other_pid) {
		waitpid(other_pid, &rc, 0);
		EXPECT_TRUE(WIFEXITED(rc));
		EXPECT_EQ(0, WEXITSTATUS(rc));
	} else {
		exit(0);
	}
}

/*
 * Does a pdfork()ed process die correctly when released?
 * So far, we only test whether it zombifies - we need pdwait4() to reap it.
 */

static char getstate(int pid)
{
	char s[1024];
	char *prompt = "State:\t";
	char ret = '?';
	FILE *f;

	snprintf(s, sizeof(s), "/proc/%d/status", pid);
	f = fopen(s, "r");
	if (!f)
		return '\0';

	while (!feof(f)) {
		fgets(s, sizeof(s), f);
		if (!strncmp(s, prompt, strlen(prompt))) {
			ret = s[strlen(prompt)];
			break;
		}
	}
	fclose(f);
	return ret;
}

#define EXPECT_PID_STATE(pid, state) EXPECT_PID_STATE2(getstate(pid), state, state)
#define EXPECT_PID_STATE2(pid, state1, state2) \
	do { \
		int _ctr = 5; \
		char _state; \
		do { \
			_state = getstate(pid); \
			if (_state == state1 || _state == state2) \
				break; \
			usleep(100000); \
		} while (--_ctr); \
		if (!_ctr) { \
			TH_LOG("Expected " #pid "('%c') in states '%c'/'%c'", \
				_state, state1, state2); \
			EXPECT_EQ(0, _ctr); \
		} \
	} while (0)

#define EXPECT_PID_ALIVE(pid) EXPECT_PID_STATE2(pid, 'R', 'S')
#define EXPECT_PID_DEAD(pid) EXPECT_PID_STATE2(pid, 'Z', '\0')

TEST_F(pdexit, release) {
	int r = 0;

	EXPECT_PID_ALIVE(self->pid);

	write(self->pipe, &r, sizeof(r));

	EXPECT_PID_DEAD(self->pid);
}

TEST_F(pdexit, close) {
	EXPECT_PID_ALIVE(self->pid);

	close(self->pd);
	EXPECT_PID_DEAD(self->pid);
}

/* Setting PD_DAEMON prevents close() from killing the child. */
TEST(close_daemon) {
	int pid, pd = -1;

	pid = pdfork(&pd, PD_DAEMON);
	ASSERT_LE(0, pid);

	if (pid == 0) {
		/* We're the child. */
		while (1)
			sleep(1);
	}

	close(pd);
	EXPECT_PID_ALIVE(pid);
}

TEST_F(pdexit, pdkill) {
	EXPECT_PID_ALIVE(self->pid);

	/* SIGCONT is ignored by default. */
	pdkill(self->pd, SIGCONT);
	EXPECT_PID_ALIVE(self->pid);

	pdkill(self->pd, SIGINT);
	EXPECT_PID_DEAD(self->pid);
}

/* The exit of a pdfork()ed process should not generate SIGCHLD. */

static void got_sigchld(int x)
{
	abort();
}

TEST_F(pdexit, no_sigchld) {
	int r = 0;

	signal(SIGCHLD, got_sigchld);
	write(self->pipe, &r, sizeof(r));
	waitpid(self->pid, &r, 0);
}

TEST(pdfork_daemon_restricted) {
	int fd, rc;

	cap_enter();
	rc = pdfork(&fd, PD_DAEMON);
	EXPECT_EQ(-1, rc);
	EXPECT_EQ(ECAPMODE, errno);

	rc = pdfork(&fd, 0);
	if (rc == 0)
		exit(0);
	EXPECT_LE(0, rc);
}

TEST_HARNESS_MAIN
