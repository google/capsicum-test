# Makefile for Capsicum kernel test module
ifeq ($(KERNELRELEASE),)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
.PHONY: build clean
build:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c modules.order Module.symvers
test: build
	-sudo insmod ./capsicum_test.ko
	-tail -20 /var/log/kern.log
else
$(info Building with KERNELRELEASE = ${KERNELRELEASE})
obj-m := capsicum_test.o
endif
