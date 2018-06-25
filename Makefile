PWD = $(shell pwd)
LINUX_KERNEL ?= $(PWD)/../linux
ARCH ?= arm64
CROSS_COMPILE ?= "$(PWD)/../toolchains/bin/aarch64-linux-gnu-"
BOARD_PLATFORM ?= bcmrpi3

obj-m += linux_pslist.o

all:
	$(MAKE) -C $(LINUX_KERNEL) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) CONFIG_DEBUG_INFO=y SUBDIRS=$(PWD) modules

kernel:
	$(MAKE) -C $(LINUX_KERNEL) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) $(BOARD_PLATFORM)_defconfig
	$(MAKE) -C $(LINUX_KERNEL) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)
