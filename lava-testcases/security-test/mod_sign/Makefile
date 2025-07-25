obj-m += hello.o

KERNELDIR := $(shell ls -d /lib/modules/$(shell uname -r)* 2>/dev/null)

all:
	make -C $(KERNELDIR)/build M=$(PWD) modules

clean:
	make -C $(KERNELDIR)/build M=$(PWD) clean
