# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
LIBBPF_OUTPUT := $(abspath ../../../contrib/libbpf/build)
APP_OUTPUT := build
CLANG ?= clang
LIBBPF_SRC := $(abspath ../../../contrib/libbpf/src)
LIBBPF_OBJ := $(abspath ../../../contrib/libbpf/build/libbpf.a)
INCLUDES := -I$(LIBBPF_OUTPUT)
CFLAGS := -g -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

APP = kprobe_connect_hook

.PHONY: all
all: $(APP_OUTPUT)/$(APP) $(APP_OUTPUT)/kprobe_connect_hook.bpf.o

msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory

.PHONY: clean
clean:
	$(call msg,CLEAN)
	rm -rf $(APP_OUTPUT) $(LIBBPF_OUTPUT)

$(APP_OUTPUT) $(LIBBPF_OUTPUT):
	$(call msg,MKDIR,$@)
	mkdir -p $@

$(APP_OUTPUT)/$(APP): %: %.o $(LIBBPF_OBJ) | $(APP_OUTPUT)
	$(call msg,BINARY,$@)
	$(CC) $(CFLAGS) $^ -lelf -lz -o $@

$(APP_OUTPUT)/%.o: %.c $(LIBBPF_OBJ) $(wildcard %.h) | $(APP_OUTPUT)
	$(call msg,CC,$@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(APP_OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) | $(APP_OUTPUT)
	$(call msg,BPF,$@)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		\
			$(INCLUDES) -c $(filter %.c,$^) -o $@

# Build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(LIBBPF_OUTPUT)
	$(call msg,LIB,$@)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 NO_PKG_CONFIG=1	\
		OBJDIR=$(LIBBPF_OUTPUT)/obj DESTDIR=$(LIBBPF_OUTPUT)	\
		INCLUDEDIR= LIBDIR= UAPIDIR=	\
		install

# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

