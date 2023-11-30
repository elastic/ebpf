obj-m += simple-kmod.o

ifndef KVER
KVER=$(shell uname -r)
endif

ifndef KMODVER
KMODVER=$(shell git describe HEAD 2>/dev/null || git rev-parse --short HEAD)
endif

buildprep:
	# elfutils-libelf-devel is needed on EL8 systems
	sudo yum install -y gcc kernel-{core,devel,modules}-$(KVER) elfutils-libelf-devel
all:
#	make -C /home/mst/Desktop/endpoint/git/endpoint-dev/Kernel/Ebpf/testing/kernel_builder/kernels/src/linux-6.3 M=$(PWD) modules
#	make -C $(BUILT_HEADERS_PATH) M=$(PWD) modules
#	make -C $(BUILT_HEADERS_PATH) M=$(PWD) modules
	#make -C $(BUILT_HEADERS_PATH) M=$(PWD) KBUILD_MODPOST_WARN=1 EXTRA_CFLAGS=-DKMODVER=\\\"$(KMODVER)\\\" modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C $(BUILT_HEADERS_PATH) M=$(PWD) clean
	rm -f spkut
install:
	sudo install -v -m 755 spkut /bin/
	sudo install -v -m 755 -d /lib/modules/$(KVER)/
	sudo install -v -m 644 simple-kmod.ko        /lib/modules/$(KVER)/simple-kmod.ko
	sudo depmod -a
