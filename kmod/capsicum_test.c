#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/task_work.h>
#include <linux/syscalls.h>
#include <linux/capsicum.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include "test_harness.h"
#include "../capsicum-rights.h"

/* Local copy of sys_dup */

unsigned int do_dup(unsigned int fildes)
{
	int ret = -EBADF;
	struct file *file = fget_raw_no_unwrap(fildes);

	if (!IS_ERR(file)) {
		ret = get_unused_fd();
		if (ret >= 0)
			fd_install(ret, file);
		else
			fput(file);
	} else {
		ret = PTR_ERR(file);
	}
	return ret;
}

/* Test the wrapping and unwrapping of file descriptors in capabilities. */
FIXTURE(new_cap) {
	struct file *orig;
	int orig_refs;
	struct cap_rights rights;
	int cap;
	struct file *capf;
};

FIXTURE_SETUP(new_cap) {
	struct cap_rights none;
	cap_rights_init(&none, 0);
	self->orig = fget(0, &none);
	ASSERT_FALSE(IS_ERR(self->orig));
	self->orig_refs = file_count(self->orig);

	/* Create a new FD to use for the test: +1 ref (from fdtable) */
	self->cap = do_dup(0);
	ASSERT_GE(self->cap, 0);
	EXPECT_EQ(self->orig_refs + 1, file_count(self->orig));

	/* Limit its rights */
	cap_rights_init(&self->rights, CAP_READ, CAP_WRITE, CAP_SEEK);
	ASSERT_EQ(0, capsicum_rights_limit(self->cap, &self->rights));
	/* Delta:
	 *  +1 ref on underlying (from wrapper)
	 *  -1 ref on underlying (removed from fdtable) */
	EXPECT_EQ(self->orig_refs + 1, file_count(self->orig));

	self->capf = fcheck(self->cap);
	ASSERT_NE(self->capf, NULL);
	EXPECT_EQ(1, file_count(self->capf));
}

FIXTURE_TEARDOWN(new_cap) {
	if (self->orig_refs > 0)
		EXPECT_EQ(self->orig_refs + 1, file_count(self->orig));
	fput(self->orig);
	sys_close(self->cap);
}

TEST_F(new_cap, init_ok) {
	struct cap_rights rights;
	struct file *f;

	EXPECT_LT(1, file_count(self->orig));
	EXPECT_EQ(1, file_count(self->capf));

	f = capsicum_unwrap(self->capf, &rights);
	/* Verify that the rights are as we set them in setup. */
	EXPECT_EQ(self->rights.cr_rights[0], rights.cr_rights[0]);
	EXPECT_EQ(self->rights.cr_rights[1], rights.cr_rights[1]);
	EXPECT_EQ(self->orig, f);
}

TEST_F(new_cap, rewrap) {
	/* When we wrap an fd in a capability, then wrap that second fd
	 * in another capability, the new capability will refer to the same
	 * original file, and the reference count of the original file
	 * will be incremented. */
	struct file *f, *unwrapped_file;
	struct cap_rights none;
	struct cap_rights rights;
	int old_count, fd, rc;
	cap_rights_init(&none, 0);
	old_count = file_count(self->orig);

	fd = do_dup(self->cap);
	ASSERT_GT(fd, 0);
	rc = capsicum_rights_limit(fd, &none);
	EXPECT_EQ(0, rc);
	f = fcheck(fd);

	unwrapped_file = capsicum_unwrap(f, &rights);
	EXPECT_EQ(none.cr_rights[0], rights.cr_rights[0]);
	EXPECT_EQ(none.cr_rights[1], rights.cr_rights[1]);
	EXPECT_EQ(self->orig, unwrapped_file);
	EXPECT_EQ(old_count + 1, file_count(self->orig));
	sys_close(fd);

	/* Closing the fd won't immediately update the refcount on orig,
	 * so disable the fixture shutdown check */
	self->orig_refs = -1;
}

TEST_F(new_cap, is_cap) {
	EXPECT_TRUE(capsicum_is_cap(self->capf));
	EXPECT_FALSE(capsicum_is_cap(self->orig));
}


TEST_F(new_cap, fget) {
	struct cap_rights none;
	struct file *f = fget(self->cap, cap_rights_init(&none, 0));

	EXPECT_EQ(self->orig, f);
	EXPECT_EQ(1, file_count(fcheck(self->cap)));
	EXPECT_EQ(self->orig_refs + 2, file_count(self->orig));

	fput(f);
}

TEST_F(new_cap, fget_light) {
	int fpn;
	struct cap_rights none;
	struct file *f = fget_light(self->cap, cap_rights_init(&none, 0), &fpn);

	EXPECT_EQ(self->orig, f);
	EXPECT_FALSE(fpn);
	EXPECT_EQ(self->orig_refs + 1, file_count(self->orig));

	fput_light(f, fpn);
}

TEST_F(new_cap, fget_raw) {
	struct cap_rights none;
	struct file *f = fget_raw(self->cap, cap_rights_init(&none, 0));

	EXPECT_EQ(f, self->orig);
	EXPECT_EQ(file_count(fcheck(self->cap)), 1);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+2);

	fput(f);
}

TEST_F(new_cap, fget_raw_light) {
	int fpn;
	struct cap_rights none;
	struct file *f = fget_raw_light(self->cap, cap_rights_init(&none, 0), NULL, &fpn);

	EXPECT_EQ(f, self->orig);
	EXPECT_EQ(fpn, 0);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+1);

	fput_light(f, fpn);
}

static int test_init(void)
{
	printk(KERN_INFO "Load capsicum_test module\n");

	/* Explicitly register tests */
	REGISTER_FIXTURE(new_cap);
	REGISTER_FIXTURE(fget);
	REGISTER_TEST_F(new_cap, init_ok);
	REGISTER_TEST_F(new_cap, rewrap);
	REGISTER_TEST_F(new_cap, is_cap);
	REGISTER_TEST_F(new_cap, fget);
	REGISTER_TEST_F(new_cap, fget_light);
	REGISTER_TEST_F(new_cap, fget_raw);
	REGISTER_TEST_F(new_cap, fget_raw_light);
	test_harness_run(NULL);

	/* We've run the tests as part of module load processing, so don't load */
	return -ENOSYS;
}

static void test_exit(void)
{
	/* should never happen */
	printk(KERN_INFO "Unload capsicum_test module\n");
}

module_init(test_init);
module_exit(test_exit);
MODULE_DESCRIPTION("Capsicum kernel test module");
MODULE_LICENSE("Dual BSD/GPL");
