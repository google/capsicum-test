/*-
 * Copyright (c) 2013 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Pawel Jakub Dawidek under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define _GNU_SOURCE  /* For getgrent_r */
#include <sys/cdefs.h>

#include <sys/capsicum.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libcasper.h>

#include "cap_grp/cap_grp.h"
#include "test.h"

#define SAVED_GROUP_COUNT 6
static int grpids[SAVED_GROUP_COUNT];
static char *grpnames[SAVED_GROUP_COUNT];

static void save_groups()
{
	int ii;
	setgrent();
	for (ii = 0; ii < SAVED_GROUP_COUNT; ii++) {
		struct group *grp = getgrent();
		grpids[ii] = grp->gr_gid;
		grpnames[ii] = strdup(grp->gr_name);
	}
	endgrent();
}
static void free_groups()
{
	int ii;
	for (ii = 0; ii < SAVED_GROUP_COUNT; ii++) {
		free(grpnames[ii]);
		grpnames[ii] = NULL;
	}
}

#define	GETGRENT0	0x0001
#define	GETGRENT1	0x0002
#define	GETGRENT2	0x0004
#define	GETGRENT	(GETGRENT0 | GETGRENT1 | GETGRENT2)
#define	GETGRENT_R0	0x0008
#define	GETGRENT_R1	0x0010
#define	GETGRENT_R2	0x0020
#define	GETGRENT_R	(GETGRENT_R0 | GETGRENT_R1 | GETGRENT_R2)
#define	GETGRNAM	0x0040
#define	GETGRNAM_R	0x0080
#define	GETGRGID	0x0100
#define	GETGRGID_R	0x0200
#define	SETGRENT	0x0400

static bool
group_mem_compare(char **mem0, char **mem1)
{
	int i0, i1;

	if (mem0 == NULL && mem1 == NULL)
		return (true);
	if (mem0 == NULL || mem1 == NULL)
		return (false);

	for (i0 = 0; mem0[i0] != NULL; i0++) {
		for (i1 = 0; mem1[i1] != NULL; i1++) {
			if (strcmp(mem0[i0], mem1[i1]) == 0)
				break;
		}
		if (mem1[i1] == NULL)
			return (false);
	}

	return (true);
}

static bool
group_compare(const struct group *grp0, const struct group *grp1)
{

	if (grp0 == NULL && grp1 == NULL)
		return (true);
	if (grp0 == NULL || grp1 == NULL)
		return (false);

	if (strcmp(grp0->gr_name, grp1->gr_name) != 0)
		return (false);

	if (grp0->gr_passwd != NULL || grp1->gr_passwd != NULL) {
		if (grp0->gr_passwd == NULL || grp1->gr_passwd == NULL)
			return (false);
		if (strcmp(grp0->gr_passwd, grp1->gr_passwd) != 0)
			return (false);
	}

	if (grp0->gr_gid != grp1->gr_gid)
		return (false);

	if (!group_mem_compare(grp0->gr_mem, grp1->gr_mem))
		return (false);

	return (true);
}

static unsigned int
runtest_cmds(cap_channel_t *capgrp)
{
	char bufs[1024], bufc[1024];
	unsigned int result;
	struct group *grps, *grpc;
	struct group sts, stc;

	result = 0;

	(void)setgrent();
	if (cap_setgrent(capgrp) == 1)
		result |= SETGRENT;

	grps = getgrent();
	grpc = cap_getgrent(capgrp);
	if (group_compare(grps, grpc)) {
		result |= GETGRENT0;
		grps = getgrent();
		grpc = cap_getgrent(capgrp);
		if (group_compare(grps, grpc))
			result |= GETGRENT1;
	}

	getgrent_r(&sts, bufs, sizeof(bufs), &grps);
	cap_getgrent_r(capgrp, &stc, bufc, sizeof(bufc), &grpc);
	if (group_compare(grps, grpc)) {
		result |= GETGRENT_R0;
		getgrent_r(&sts, bufs, sizeof(bufs), &grps);
		cap_getgrent_r(capgrp, &stc, bufc, sizeof(bufc), &grpc);
		if (group_compare(grps, grpc))
			result |= GETGRENT_R1;
	}

	(void)setgrent();
	if (cap_setgrent(capgrp) == 1)
		result |= SETGRENT;

	getgrent_r(&sts, bufs, sizeof(bufs), &grps);
	cap_getgrent_r(capgrp, &stc, bufc, sizeof(bufc), &grpc);
	if (group_compare(grps, grpc))
		result |= GETGRENT_R2;

	grps = getgrent();
	grpc = cap_getgrent(capgrp);
	if (group_compare(grps, grpc))
		result |= GETGRENT2;

	grps = getgrnam(grpnames[0]);
	grpc = cap_getgrnam(capgrp, grpnames[0]);
	if (group_compare(grps, grpc)) {
		grps = getgrnam(grpnames[5]);
		grpc = cap_getgrnam(capgrp, grpnames[5]);
		if (group_compare(grps, grpc))
			result |= GETGRNAM;
	}

	getgrnam_r(grpnames[0], &sts, bufs, sizeof(bufs), &grps);
	cap_getgrnam_r(capgrp, grpnames[0], &stc, bufc, sizeof(bufc), &grpc);
	if (group_compare(grps, grpc)) {
		getgrnam_r(grpnames[5], &sts, bufs, sizeof(bufs), &grps);
		cap_getgrnam_r(capgrp, grpnames[5], &stc, bufc, sizeof(bufc),
		    &grpc);
		if (group_compare(grps, grpc))
			result |= GETGRNAM_R;
	}

	grps = getgrgid(grpids[0]);
	grpc = cap_getgrgid(capgrp, grpids[0]);
	if (group_compare(grps, grpc)) {
		grps = getgrgid(grpids[5]);
		grpc = cap_getgrgid(capgrp, grpids[5]);
		if (group_compare(grps, grpc))
			result |= GETGRGID;
	}

	getgrgid_r(grpids[0], &sts, bufs, sizeof(bufs), &grps);
	cap_getgrgid_r(capgrp, grpids[0], &stc, bufc, sizeof(bufc), &grpc);
	if (group_compare(grps, grpc)) {
		getgrgid_r(grpids[5], &sts, bufs, sizeof(bufs), &grps);
		cap_getgrgid_r(capgrp, grpids[5], &stc, bufc, sizeof(bufc),
		    &grpc);
		if (group_compare(grps, grpc))
			result |= GETGRGID_R;
	}

	return (result);
}

static void
test_cmds(cap_channel_t *origcapgrp)
{
	cap_channel_t *capgrp;
	const char *cmds[7], *fields[4], *names[5];
	gid_t gids[5];

	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";

	names[0] = grpnames[0];
	names[1] = grpnames[1];
	names[2] = grpnames[2];
	names[3] = grpnames[3];
	names[4] = grpnames[5];

	gids[0] = grpids[0];
	gids[1] = grpids[1];
	gids[2] = grpids[2];
	gids[3] = grpids[3];
	gids[4] = grpids[5];

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrent_r, getgrnam, getgrnam_r,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names: entries 0, 1, 2, 3, 5
	 *     gids:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == 0);
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == 0);
	CHECK(cap_grp_limit_groups(capgrp, names, 5, NULL, 0) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT | GETGRENT_R |
	    GETGRNAM | GETGRNAM_R | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrent_r, getgrnam, getgrnam_r,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names:
	 *     gids: entries 0, 1, 2, 3, 5
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == 0);
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == 0);
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 5) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT | GETGRENT_R |
	    GETGRNAM | GETGRNAM_R | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: getgrent, getgrent_r, getgrnam, getgrnam_r,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names: entries 0, 1, 2, 3, 5
	 *     gids:
	 * Disallow:
	 * cmds: setgrent
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "getgrent";
	cmds[1] = "getgrent_r";
	cmds[2] = "getgrnam";
	cmds[3] = "getgrnam_r";
	cmds[4] = "getgrgid";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "setgrent";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_groups(capgrp, names, 5, NULL, 0) == 0);

	CHECK(runtest_cmds(capgrp) == (GETGRENT0 | GETGRENT1 | GETGRENT_R0 |
	    GETGRENT_R1 | GETGRNAM | GETGRNAM_R | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: getgrent, getgrent_r, getgrnam, getgrnam_r,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names:
	 *     gids: entries 0, 1, 2, 3, 5
	 * Disallow:
	 * cmds: setgrent
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "getgrent";
	cmds[1] = "getgrent_r";
	cmds[2] = "getgrnam";
	cmds[3] = "getgrnam_r";
	cmds[4] = "getgrgid";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "setgrent";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 5) == 0);

	CHECK(runtest_cmds(capgrp) == (GETGRENT0 | GETGRENT1 | GETGRENT_R0 |
	    GETGRENT_R1 | GETGRNAM | GETGRNAM_R | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent_r, getgrnam, getgrnam_r,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names: entries 0, 1, 2, 3, 5
	 *     gids:
	 * Disallow:
	 * cmds: getgrent
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent_r";
	cmds[2] = "getgrnam";
	cmds[3] = "getgrnam_r";
	cmds[4] = "getgrgid";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrent";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == 0);
	CHECK(cap_grp_limit_groups(capgrp, names, 5, NULL, 0) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT_R2 |
	    GETGRNAM | GETGRNAM_R | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent_r, getgrnam, getgrnam_r,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names:
	 *     gids: entries 0, 1, 2, 3, 5
	 * Disallow:
	 * cmds: getgrent
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent_r";
	cmds[2] = "getgrnam";
	cmds[3] = "getgrnam_r";
	cmds[4] = "getgrgid";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrent";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == 0);
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 5) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT_R2 |
	    GETGRNAM | GETGRNAM_R | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrnam, getgrnam_r,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names: entries 0, 1, 2, 3, 5
	 *     gids:
	 * Disallow:
	 * cmds: getgrent_r
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrnam";
	cmds[3] = "getgrnam_r";
	cmds[4] = "getgrgid";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrent_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_groups(capgrp, names, 5, NULL, 0) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT0 | GETGRENT1 |
	    GETGRNAM | GETGRNAM_R | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrnam, getgrnam_r,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names:
	 *     gids: entries 0, 1, 2, 3, 5
	 * Disallow:
	 * cmds: getgrent_r
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrnam";
	cmds[3] = "getgrnam_r";
	cmds[4] = "getgrgid";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrent_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 5) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT0 | GETGRENT1 |
	    GETGRNAM | GETGRNAM_R | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrent_r, getgrnam_r,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names: entries 0, 1, 2, 3, 5
	 *     gids:
	 * Disallow:
	 * cmds: getgrnam
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam_r";
	cmds[4] = "getgrgid";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrnam";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == 0);
	CHECK(cap_grp_limit_groups(capgrp, names, 5, NULL, 0) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT | GETGRENT_R |
	    GETGRNAM_R | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrent_r, getgrnam_r,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names:
	 *     gids: entries 0, 1, 2, 3, 5
	 * Disallow:
	 * cmds: getgrnam
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam_r";
	cmds[4] = "getgrgid";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrnam";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == 0);
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 5) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT | GETGRENT_R |
	    GETGRNAM_R | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrent_r, getgrnam,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names: entries 0, 1, 2, 3, 5
	 *     gids:
	 * Disallow:
	 * cmds: getgrnam_r
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrgid";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrnam_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_groups(capgrp, names, 5, NULL, 0) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT | GETGRENT_R |
	    GETGRNAM | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrent_r, getgrnam,
	 *       getgrgid, getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names:
	 *     gids: entries 0, 1, 2, 3, 5
	 * Disallow:
	 * cmds: getgrnam_r
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrgid";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrnam_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 5) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT | GETGRENT_R |
	    GETGRNAM | GETGRGID | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrent_r, getgrnam, getgrnam_r,
	 *       getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names: entries 0, 1, 2, 3, 5
	 *     gids:
	 * Disallow:
	 * cmds: getgrgid
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrgid";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == 0);
	CHECK(cap_grp_limit_groups(capgrp, names, 5, NULL, 0) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT | GETGRENT_R |
	    GETGRNAM | GETGRNAM_R | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrent_r, getgrnam, getgrnam_r,
	 *       getgrgid_r
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names:
	 *     gids: entries 0, 1, 2, 3, 5
	 * Disallow:
	 * cmds: getgrgid
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrgid";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == 0);
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 5) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT | GETGRENT_R |
	    GETGRNAM | GETGRNAM_R | GETGRGID_R));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrent_r, getgrnam, getgrnam_r,
	 *       getgrgid
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names: entries 0, 1, 2, 3, 5
	 *     gids:
	 * Disallow:
	 * cmds: getgrgid_r
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_groups(capgrp, names, 5, NULL, 0) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT | GETGRENT_R |
	    GETGRNAM | GETGRNAM_R | GETGRGID));

	cap_close(capgrp);

	/*
	 * Allow:
	 * cmds: setgrent, getgrent, getgrent_r, getgrnam, getgrnam_r,
	 *       getgrgid
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 * groups:
	 *     names:
	 *     gids: entries 0, 1, 2, 3, 5
	 * Disallow:
	 * cmds: getgrgid_r
	 * fields:
	 * groups:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 6) == 0);
	cmds[0] = "setgrent";
	cmds[1] = "getgrent";
	cmds[2] = "getgrent_r";
	cmds[3] = "getgrnam";
	cmds[4] = "getgrnam_r";
	cmds[5] = "getgrgid";
	cmds[6] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 7) == -1 && errno == ENOTCAPABLE);
	cmds[0] = "getgrgid_r";
	CHECK(cap_grp_limit_cmds(capgrp, cmds, 1) == -1 && errno == ENOTCAPABLE);
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 5) == 0);

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT | GETGRENT_R |
	    GETGRNAM | GETGRNAM_R | GETGRGID));

	cap_close(capgrp);
}

#define	GR_NAME		0x01
#define	GR_PASSWD	0x02
#define	GR_GID		0x04
#define	GR_MEM		0x08

static unsigned int
group_fields(const struct group *grp)
{
	unsigned int result;

	result = 0;

	if (!grp)
		return (result);
	if (grp->gr_name != NULL && grp->gr_name[0] != '\0')
		result |= GR_NAME;

	if (grp->gr_passwd != NULL && grp->gr_passwd[0] != '\0')
		result |= GR_PASSWD;

	if (grp->gr_gid != (gid_t)-1)
		result |= GR_GID;

	if (grp->gr_mem != NULL && grp->gr_mem[0] != NULL)
		result |= GR_MEM;

	return (result);
}

static bool
runtest_fields(cap_channel_t *capgrp, unsigned int expected)
{
	char buf[1024];
	struct group *grp;
	struct group st;

	(void)cap_setgrent(capgrp);
	grp = cap_getgrent(capgrp);
	if (group_fields(grp) != expected)
		return (false);

	(void)cap_setgrent(capgrp);
	cap_getgrent_r(capgrp, &st, buf, sizeof(buf), &grp);
	if (group_fields(grp) != expected)
		return (false);

	grp = cap_getgrnam(capgrp, grpnames[0]);
	if (group_fields(grp) != expected)
		return (false);

	cap_getgrnam_r(capgrp, grpnames[0], &st, buf, sizeof(buf), &grp);
	if (group_fields(grp) != expected)
		return (false);

	grp = cap_getgrgid(capgrp, grpids[0]);
	if (group_fields(grp) != expected)
		return (false);

	cap_getgrgid_r(capgrp, grpids[0], &st, buf, sizeof(buf), &grp);
	if (group_fields(grp) != expected)
		return (false);

	return (true);
}

static void
test_fields(cap_channel_t *origcapgrp)
{
	cap_channel_t *capgrp;
	const char *fields[4];

	/* No limits. */

	CHECK(runtest_fields(origcapgrp, GR_NAME | GR_PASSWD | GR_GID | GR_MEM));

	/*
	 * Allow:
	 * fields: gr_name, gr_passwd, gr_gid, gr_mem
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == 0);

	CHECK(runtest_fields(capgrp, GR_NAME | GR_PASSWD | GR_GID | GR_MEM));

	cap_close(capgrp);

	/*
	 * Allow:
	 * fields: gr_passwd, gr_gid, gr_mem
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	fields[0] = "gr_passwd";
	fields[1] = "gr_gid";
	fields[2] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 3) == 0);
	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == -1 &&
	    errno == ENOTCAPABLE);

	CHECK(runtest_fields(capgrp, GR_PASSWD | GR_GID | GR_MEM));

	cap_close(capgrp);

	/*
	 * Allow:
	 * fields: gr_name, gr_gid, gr_mem
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	fields[0] = "gr_name";
	fields[1] = "gr_gid";
	fields[2] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 3) == 0);
	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == -1 &&
	    errno == ENOTCAPABLE);
	fields[0] = "gr_passwd";
	CHECK(cap_grp_limit_fields(capgrp, fields, 1) == -1 &&
	    errno == ENOTCAPABLE);

	CHECK(runtest_fields(capgrp, GR_NAME | GR_GID | GR_MEM));

	cap_close(capgrp);

	/*
	 * Allow:
	 * fields: gr_name, gr_passwd, gr_mem
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 3) == 0);
	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == -1 &&
	    errno == ENOTCAPABLE);
	fields[0] = "gr_gid";
	CHECK(cap_grp_limit_fields(capgrp, fields, 1) == -1 &&
	    errno == ENOTCAPABLE);

	CHECK(runtest_fields(capgrp, GR_NAME | GR_PASSWD | GR_MEM));

	cap_close(capgrp);

	/*
	 * Allow:
	 * fields: gr_name, gr_passwd, gr_gid
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	CHECK(cap_grp_limit_fields(capgrp, fields, 3) == 0);
	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == -1 &&
	    errno == ENOTCAPABLE);
	fields[0] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 1) == -1 &&
	    errno == ENOTCAPABLE);

	CHECK(runtest_fields(capgrp, GR_NAME | GR_PASSWD | GR_GID));

	cap_close(capgrp);

	/*
	 * Allow:
	 * fields: gr_name, gr_passwd
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	CHECK(cap_grp_limit_fields(capgrp, fields, 2) == 0);
	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == -1 &&
	    errno == ENOTCAPABLE);
	fields[0] = "gr_gid";
	CHECK(cap_grp_limit_fields(capgrp, fields, 1) == -1 &&
	    errno == ENOTCAPABLE);

	CHECK(runtest_fields(capgrp, GR_NAME | GR_PASSWD));

	cap_close(capgrp);

	/*
	 * Allow:
	 * fields: gr_name, gr_gid
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	fields[0] = "gr_name";
	fields[1] = "gr_gid";
	CHECK(cap_grp_limit_fields(capgrp, fields, 2) == 0);
	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == -1 &&
	    errno == ENOTCAPABLE);
	fields[0] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 1) == -1 &&
	    errno == ENOTCAPABLE);

	CHECK(runtest_fields(capgrp, GR_NAME | GR_GID));

	cap_close(capgrp);

	/*
	 * Allow:
	 * fields: gr_name, gr_mem
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	fields[0] = "gr_name";
	fields[1] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 2) == 0);
	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == -1 &&
	    errno == ENOTCAPABLE);
	fields[0] = "gr_passwd";
	CHECK(cap_grp_limit_fields(capgrp, fields, 1) == -1 &&
	    errno == ENOTCAPABLE);

	CHECK(runtest_fields(capgrp, GR_NAME | GR_MEM));

	cap_close(capgrp);

	/*
	 * Allow:
	 * fields: gr_passwd, gr_gid
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	fields[0] = "gr_passwd";
	fields[1] = "gr_gid";
	CHECK(cap_grp_limit_fields(capgrp, fields, 2) == 0);
	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == -1 &&
	    errno == ENOTCAPABLE);
	fields[0] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 1) == -1 &&
	    errno == ENOTCAPABLE);

	CHECK(runtest_fields(capgrp, GR_PASSWD | GR_GID));

	cap_close(capgrp);

	/*
	 * Allow:
	 * fields: gr_passwd, gr_mem
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	fields[0] = "gr_passwd";
	fields[1] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 2) == 0);
	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == -1 &&
	    errno == ENOTCAPABLE);
	fields[0] = "gr_gid";
	CHECK(cap_grp_limit_fields(capgrp, fields, 1) == -1 &&
	    errno == ENOTCAPABLE);

	CHECK(runtest_fields(capgrp, GR_PASSWD | GR_MEM));

	cap_close(capgrp);

	/*
	 * Allow:
	 * fields: gr_gid, gr_mem
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	fields[0] = "gr_gid";
	fields[1] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 2) == 0);
	fields[0] = "gr_name";
	fields[1] = "gr_passwd";
	fields[2] = "gr_gid";
	fields[3] = "gr_mem";
	CHECK(cap_grp_limit_fields(capgrp, fields, 4) == -1 &&
	    errno == ENOTCAPABLE);
	fields[0] = "gr_passwd";
	CHECK(cap_grp_limit_fields(capgrp, fields, 1) == -1 &&
	    errno == ENOTCAPABLE);

	CHECK(runtest_fields(capgrp, GR_GID | GR_MEM));

	cap_close(capgrp);
}

static bool
runtest_groups(cap_channel_t *capgrp, const char **names, const gid_t *gids,
    size_t ngroups)
{
	char buf[1024];
	struct group *grp;
	struct group st;
	unsigned int i, got;

	(void)cap_setgrent(capgrp);
	got = 0;
	for (;;) {
		grp = cap_getgrent(capgrp);
		if (grp == NULL)
			break;
		got++;
		for (i = 0; i < ngroups; i++) {
			if (strcmp(names[i], grp->gr_name) == 0 &&
			    gids[i] == grp->gr_gid) {
				break;
			}
		}
		if (i == ngroups)
			return (false);
	}
	if (got != ngroups)
		return (false);

	(void)cap_setgrent(capgrp);
	got = 0;
	for (;;) {
		cap_getgrent_r(capgrp, &st, buf, sizeof(buf), &grp);
		if (grp == NULL)
			break;
		got++;
		for (i = 0; i < ngroups; i++) {
			if (strcmp(names[i], grp->gr_name) == 0 &&
			    gids[i] == grp->gr_gid) {
				break;
			}
		}
		if (i == ngroups)
			return (false);
	}
	if (got != ngroups)
		return (false);

	for (i = 0; i < ngroups; i++) {
		grp = cap_getgrnam(capgrp, names[i]);
		if (grp == NULL)
			return (false);
	}

	for (i = 0; i < ngroups; i++) {
		cap_getgrnam_r(capgrp, names[i], &st, buf, sizeof(buf), &grp);
		if (grp == NULL)
			return (false);
	}

	for (i = 0; i < ngroups; i++) {
		grp = cap_getgrgid(capgrp, gids[i]);
		if (grp == NULL)
			return (false);
	}

	for (i = 0; i < ngroups; i++) {
		cap_getgrgid_r(capgrp, gids[i], &st, buf, sizeof(buf), &grp);
		if (grp == NULL)
			return (false);
	}

	return (true);
}

static void
test_groups(cap_channel_t *origcapgrp)
{
	cap_channel_t *capgrp;
	const char *names[5];
	gid_t gids[5];

	/*
	 * Allow:
	 * groups:
	 *     names: entries 0, 1, 2, 3, 4
	 *     gids:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	names[0] = grpnames[0];
	names[1] = grpnames[1];
	names[2] = grpnames[2];
	names[3] = grpnames[3];
	names[4] = grpnames[4];
	CHECK(cap_grp_limit_groups(capgrp, names, 5, NULL, 0) == 0);
	gids[0] = grpids[0];
	gids[1] = grpids[1];
	gids[2] = grpids[2];
	gids[3] = grpids[3];
	gids[4] = grpids[4];

	CHECK(runtest_groups(capgrp, names, gids, 5));

	cap_close(capgrp);

	/*
	 * Allow:
	 * groups:
	 *     names: entries 2, 3, 4
	 *     gids:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	names[0] = grpnames[2];
	names[1] = grpnames[3];
	names[2] = grpnames[4];
	CHECK(cap_grp_limit_groups(capgrp, names, 3, NULL, 0) == 0);
	names[3] = grpnames[1];
	CHECK(cap_grp_limit_groups(capgrp, names, 4, NULL, 0) == -1 &&
	    errno == ENOTCAPABLE);
	names[0] = grpnames[1];
	CHECK(cap_grp_limit_groups(capgrp, names, 1, NULL, 0) == -1 &&
	    errno == ENOTCAPABLE);
	names[0] = grpnames[2];
	gids[0] = grpids[2];
	gids[1] = grpids[3];
	gids[2] = grpids[4];

	CHECK(runtest_groups(capgrp, names, gids, 3));

	cap_close(capgrp);

	/*
	 * Allow:
	 * groups:
	 *     names: entries 0, 2, 4
	 *     gids:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	names[0] = grpnames[0];
	names[1] = grpnames[2];
	names[2] = grpnames[4];
	CHECK(cap_grp_limit_groups(capgrp, names, 3, NULL, 0) == 0);
	names[3] = grpnames[1];
	CHECK(cap_grp_limit_groups(capgrp, names, 4, NULL, 0) == -1 &&
	    errno == ENOTCAPABLE);
	names[0] = grpnames[1];
	CHECK(cap_grp_limit_groups(capgrp, names, 1, NULL, 0) == -1 &&
	    errno == ENOTCAPABLE);
	names[0] = grpnames[0];
	gids[0] = grpids[0];
	gids[1] = grpids[2];
	gids[2] = grpids[4];

	CHECK(runtest_groups(capgrp, names, gids, 3));

	cap_close(capgrp);

	/*
	 * Allow:
	 * groups:
	 *     names:
	 *     gids: 2, 3, 4
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	names[0] = grpnames[2];
	names[1] = grpnames[3];
	names[2] = grpnames[4];
	gids[0] = grpids[2];
	gids[1] = grpids[3];
	gids[2] = grpids[4];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 3) == 0);
	gids[3] = grpids[0];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 4) == -1 &&
	    errno == ENOTCAPABLE);
	gids[0] = grpids[0];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 1) == -1 &&
	    errno == ENOTCAPABLE);
	gids[0] = grpids[2];

	CHECK(runtest_groups(capgrp, names, gids, 3));

	cap_close(capgrp);

	/*
	 * Allow:
	 * groups:
	 *     names:
	 *     gids: 0, 2, 4
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	names[0] = grpnames[0];
	names[1] = grpnames[2];
	names[2] = grpnames[4];
	gids[0] = grpids[0];
	gids[1] = grpids[2];
	gids[2] = grpids[4];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 3) == 0);
	gids[3] = grpids[1];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 4) == -1 &&
	    errno == ENOTCAPABLE);
	gids[0] = grpids[1];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 1) == -1 &&
	    errno == ENOTCAPABLE);
	gids[0] = grpids[0];

	CHECK(runtest_groups(capgrp, names, gids, 3));

	cap_close(capgrp);

	/*
	 * Allow:
	 * groups:
	 *     names: entry 2
	 *     gids:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	names[0] = grpnames[2];
	CHECK(cap_grp_limit_groups(capgrp, names, 1, NULL, 0) == 0);
	names[1] = grpnames[1];
	CHECK(cap_grp_limit_groups(capgrp, names, 2, NULL, 0) == -1 &&
	    errno == ENOTCAPABLE);
	names[0] = grpnames[1];
	CHECK(cap_grp_limit_groups(capgrp, names, 1, NULL, 0) == -1 &&
	    errno == ENOTCAPABLE);
	names[0] = grpnames[2];
	gids[0] = grpids[2];

	CHECK(runtest_groups(capgrp, names, gids, 1));

	cap_close(capgrp);

	/*
	 * Allow:
	 * groups:
	 *     names: entries 0, 4
	 *     gids:
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	names[0] = grpnames[0];
	names[1] = grpnames[4];
	CHECK(cap_grp_limit_groups(capgrp, names, 2, NULL, 0) == 0);
	names[2] = grpnames[1];
	CHECK(cap_grp_limit_groups(capgrp, names, 3, NULL, 0) == -1 &&
	    errno == ENOTCAPABLE);
	names[0] = grpnames[1];
	CHECK(cap_grp_limit_groups(capgrp, names, 1, NULL, 0) == -1 &&
	    errno == ENOTCAPABLE);
	names[0] = grpnames[0];
	gids[0] = grpids[0];
	gids[1] = grpids[4];

	CHECK(runtest_groups(capgrp, names, gids, 2));

	cap_close(capgrp);

	/*
	 * Allow:
	 * groups:
	 *     names:
	 *     gids: 2
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	names[0] = grpnames[2];
	gids[0] = grpids[2];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 1) == 0);
	gids[1] = grpids[1];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 2) == -1 &&
	    errno == ENOTCAPABLE);
	gids[0] = grpids[1];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 1) == -1 &&
	    errno == ENOTCAPABLE);
	gids[0] = grpids[2];

	CHECK(runtest_groups(capgrp, names, gids, 1));

	cap_close(capgrp);

	/*
	 * Allow:
	 * groups:
	 *     names:
	 *     gids: 0, 4
	 */
	capgrp = cap_clone(origcapgrp);
	CHECK(capgrp != NULL);

	names[0] = grpnames[0];
	names[1] = grpnames[4];
	gids[0] = grpids[0];
	gids[1] = grpids[4];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 2) == 0);
	gids[2] = grpids[1];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 3) == -1 &&
	    errno == ENOTCAPABLE);
	gids[0] = grpids[1];
	CHECK(cap_grp_limit_groups(capgrp, NULL, 0, gids, 1) == -1 &&
	    errno == ENOTCAPABLE);
	gids[0] = grpids[0];

	CHECK(runtest_groups(capgrp, names, gids, 2));

	cap_close(capgrp);
}

int
main(void)
{
	cap_channel_t *capcas, *capgrp;

	save_groups();
	printf("1..199\n");

	capcas = cap_init();
	CHECKX(capcas != NULL);

	capgrp = cap_service_open(capcas, "system.grp");
	CHECKX(capgrp != NULL);

	cap_close(capcas);

	/* No limits. */

	CHECK(runtest_cmds(capgrp) == (SETGRENT | GETGRENT | GETGRENT_R |
	    GETGRNAM | GETGRNAM_R | GETGRGID | GETGRGID_R));

	test_cmds(capgrp);

	test_fields(capgrp);

	test_groups(capgrp);

	cap_close(capgrp);

	free_groups();
	exit(failures);
}
