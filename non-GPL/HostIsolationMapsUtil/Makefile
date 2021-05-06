# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
LIBBPF_OUTPUT := $(abspath ../../contrib/libbpf/build)
LIBBPF_INCLUDE := $(abspath ../../contrib/libbpf/include/uapi)
COMMON_DIR := $(abspath ../Common)
APP_OUTPUT := build
CLANG ?= clang
LIBBPF_SRC := $(abspath ../../contrib/libbpf/src)
LIBBPF_OBJ := $(abspath ../../contrib/libbpf/build/libbpf.a)
INCLUDES := -I$(LIBBPF_OUTPUT) -I$(LIBBPF_INCLUDE) -I$(COMMON_DIR)
CFLAGS := -g -O2 -Wall

APPS = $(APP_OUTPUT)/update_IPs $(APP_OUTPUT)/update_pids

.PHONY: all
ifndef BUILD_STATIC_LIB
all: $(APPS)
else
all: $(APP_OUTPUT)/update_maps.o
endif

msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory

.PHONY: clean
clean:
	$(call msg,CLEAN)
	rm -rf $(APP_OUTPUT) $(LIBBPF_OUTPUT)

$(APP_OUTPUT) $(LIBBPF_OUTPUT):
	$(call msg,MKDIR,$@)
	mkdir -p $@

$(APPS): %: %.o $(APP_OUTPUT)/update_maps.o $(LIBBPF_OBJ) $(COMMON_DIR)/Common.o | $(APP_OUTPUT)
	$(call msg,BINARY,$@)
	$(CC) $(CFLAGS) $^ -lelf -lz -o $@ 

$(APP_OUTPUT)/%.o: %.c $(LIBBPF_OBJ) $(COMMON_DIR)/Common.o $(wildcard %.h) | $(APP_OUTPUT)
	$(call msg,CC,$@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(APP_OUTPUT)/update_maps.o: update_maps.c update_maps.h $(LIBBPF_OBJ) $(COMMON_DIR)/Common.o | $(APP_OUTPUT)
	$(call msg,CC,$@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build eBPF common
$(COMMON_DIR)/Common.o: $(COMMON_DIR)/Common.c $(COMMON_DIR)/Common.h $(LIBBPF_OBJ)
	$(call msg,CC,$@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(LIBBPF_OUTPUT)
	$(call msg,LIB,$@)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 NO_PKG_CONFIG=1	      \
		    OBJDIR=$(LIBBPF_OUTPUT)/obj DESTDIR=$(LIBBPF_OUTPUT)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

