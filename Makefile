#grabbed this from blog.markloiseau.com
obj-m := refmon.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CC := gcc

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
