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

/* Test the wrapping and unwrapping of file descriptors in capabilities. */
FIXTURE(new_cap) {
	struct file *orig;
	int cap;
	struct file *capf;
};

FIXTURE_SETUP(new_cap) {
	self->orig = fget(0, CAP_NONE);
	ASSERT_FALSE(IS_ERR(self->orig));
	self->cap = sys_cap_new(0, 0);
	ASSERT_GE(self->cap, 0);
	/* The new capability fd must not be the same as the original (0). */
	ASSERT_NE(self->cap, 0);
	self->capf = fcheck(self->cap);
	ASSERT_NE(self->capf, NULL);
}

FIXTURE_TEARDOWN(new_cap) {
	fput(self->orig);
	sys_close(self->cap);
}

TEST_F(new_cap, init_ok) {
	u64 rights;
	struct file *f;

	EXPECT_GT(file_count(self->orig), 1);
	EXPECT_EQ(file_count(self->capf), 1);

	rights = (u64)-1;
	f = capsicum_unwrap(self->capf, &rights);
	/* Verify that the rights are as we set them in setup. */
	EXPECT_EQ(rights, 0);
	EXPECT_EQ(f, self->orig);
}

TEST_F(new_cap, rewrap) {
	/* When we wrap an fd in a capability, then wrap that second fd
	 * in another capability, the new capability will refer to the same
	 * original file, and the reference count of the original file
	 * will be incremented.
	 */
	struct file *f, *unwrapped_file;
	u64 rights = CAP_NONE;

	int old_count, fd;

	old_count = file_count(self->orig);

	fd = sys_cap_new(self->cap, 0);
	ASSERT_GT(fd, 0);
	f = fcheck(fd);

	unwrapped_file = capsicum_unwrap(f, &rights);
	EXPECT_EQ(rights, 0);
	EXPECT_EQ(unwrapped_file, self->orig);
	EXPECT_EQ(file_count(self->orig), old_count + 1);
	sys_close(fd);
}

TEST_F(new_cap, is_cap) {
	EXPECT_TRUE(capsicum_is_cap(self->capf));
	EXPECT_FALSE(capsicum_is_cap(self->orig));
}


/* Test that the fget() family of functions unwraps capabilities correctly. */
FIXTURE(fget) {
	struct file *orig;
	int cap;
	int orig_refs;
};

FIXTURE_SETUP(fget) {
	self->orig = fget(0, CAP_NONE);
	self->orig_refs = file_count(self->orig);
	self->cap = sys_cap_new(0, CAP_READ|CAP_WRITE|CAP_SEEK);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+1);
	EXPECT_EQ(file_count(fcheck(self->cap)), 1);
}

FIXTURE_TEARDOWN(fget) {
	EXPECT_EQ(file_count(self->orig), self->orig_refs+1);
	sys_close(self->cap);
	fput(self->orig);
}

TEST_F(fget, fget) {
	struct file *f = fget(self->cap, CAP_NONE);

	EXPECT_EQ(f, self->orig);
	EXPECT_EQ(file_count(fcheck(self->cap)), 1);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+2);

	fput(f);
}

TEST_F(fget, fget_light) {
	int fpn;
	struct file *f = fget_light(self->cap, CAP_NONE, &fpn);

	EXPECT_EQ(f, self->orig);
	EXPECT_FALSE(fpn);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+1);

	fput_light(f, fpn);
}

TEST_F(fget, fget_raw) {
	struct file *f = fget_raw(self->cap, CAP_NONE);

	EXPECT_EQ(f, self->orig);
	EXPECT_EQ(file_count(fcheck(self->cap)), 1);
	EXPECT_EQ(file_count(self->orig), self->orig_refs+2);

	fput(f);
}

TEST_F(fget, fget_raw_light) {
	int fpn;
	struct file *f = fget_raw_light(self->cap, CAP_NONE, NULL, &fpn);

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
	REGISTER_TEST_F(fget, fget);
	REGISTER_TEST_F(fget, fget_light);
	REGISTER_TEST_F(fget, fget_raw);
	REGISTER_TEST_F(fget, fget_raw_light);
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
