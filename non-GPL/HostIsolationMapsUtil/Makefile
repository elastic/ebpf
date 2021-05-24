# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


LIBBPF_OUTPUT := $(abspath ../../contrib/libbpf/build)
LIBBPF_UAPI_INCLUDE := $(abspath ../../contrib/libbpf/include/uapi)
LIBBPF_MAIN_INCLUDE := $(abspath ../../contrib/libbpf/include)
ELFTOOLCHAIN_OUTPUT := $(abspath ../../contrib/elftoolchain/build)
COMMON_DIR := $(abspath ../Common)
APP_OUTPUT := build
CLANG ?= clang
LIBBPF_SRC := $(abspath ../../contrib/libbpf/src)
LIBBPF_OBJ := $(abspath ../../contrib/libbpf/build/libbpf.a)
INCLUDES := -I$(LIBBPF_OUTPUT) -I$(LIBBPF_UAPI_INCLUDE) -I$(LIBBPF_MAIN_INCLUDE) -I$(COMMON_DIR)
CFLAGS := -g -O2 -Wall
LDFLAGS := -L$(ELFTOOLCHAIN_OUTPUT)

APPS = $(APP_OUTPUT)/UpdateIPsDemo $(APP_OUTPUT)/UpdatePidsDemo

.PHONY: all
ifndef BUILD_STATIC_LIB
all: $(APPS)
else
all: $(APP_OUTPUT)/UpdateMaps.o
endif

msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory

.PHONY: clean
clean:
	$(call msg,CLEAN)
	rm -rf $(APP_OUTPUT) $(LIBBPF_OUTPUT)
	rm -f $(COMMON_DIR)/Common.o

$(APP_OUTPUT) $(LIBBPF_OUTPUT):
	$(call msg,MKDIR,$@)
	mkdir -p $@

$(APPS): %: %.o $(APP_OUTPUT)/UpdateMaps.o $(LIBBPF_OBJ) $(COMMON_DIR)/Common.o | $(APP_OUTPUT)
	$(call msg,BINARY,$@)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -lelf -lz -o $@

$(APP_OUTPUT)/%.o: %.c $(LIBBPF_OBJ) $(COMMON_DIR)/Common.o $(wildcard %.h) | $(APP_OUTPUT)
	$(call msg,CC,$@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build eBPF common
$(COMMON_DIR)/Common.o: $(COMMON_DIR)/Common.c $(COMMON_DIR)/Common.h $(LIBBPF_OBJ)
	$(call msg,CC,$@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(LIBBPF_OUTPUT)
	$(call msg,LIB,$@)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 NO_PKG_CONFIG=1          \
                    OBJDIR=$(LIBBPF_OUTPUT)/obj DESTDIR=$(LIBBPF_OUTPUT)      \
                    INCLUDEDIR= LIBDIR= UAPIDIR=                              \
                    CFLAGS="$(CFLAGS) -I$(ELFTOOLCHAIN_OUTPUT)"               \
                    install


# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

