#
# AgenticOS prototype -- seL4 + Microkit on QEMU virt (aarch64).
#
# Copyright 2026 the AgenticOS authors
# SPDX-License-Identifier: BSD-2-Clause
#
# Usage:
#   make MICROKIT_SDK=/path/to/microkit-sdk-2.3.1        build
#   make MICROKIT_SDK=... run                            build and boot in QEMU
#   make MICROKIT_SDK=... NET_BACKEND=virtio run-live     boot against a model endpoint
#
# scripts/setup-sdk.sh builds a matching SDK from pinned sources if you do not
# have one.
#

ifeq ($(strip $(MICROKIT_SDK)),)
$(error MICROKIT_SDK must be set; see scripts/setup-sdk.sh)
endif

BUILD_DIR       ?= build
MICROKIT_BOARD  ?= qemu_virt_aarch64
MICROKIT_CONFIG ?= debug
NET_BACKEND     ?= replay
TOOLCHAIN       ?= aarch64-none-elf

BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

# Distributions ship the bare-metal toolchain under either prefix.
ifeq ($(shell command -v $(TOOLCHAIN)-gcc 2>/dev/null),)
  TOOLCHAIN := aarch64-linux-gnu
endif

CC := $(TOOLCHAIN)-gcc
LD := $(TOOLCHAIN)-ld

MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit
SYSTEM_FILE   := board/$(MICROKIT_BOARD)/agenticos.system

CFLAGS := -nostdlib -ffreestanding -mstrict-align -g3 -O2 \
          -Wall -Wextra -Werror -Wno-unused-function \
          -Iinclude -I$(BOARD_DIR)/include
LDFLAGS := -L$(BOARD_DIR)/lib
LIBS    := -lmicrokit -Tmicrokit.ld

IMAGE_FILE  := $(BUILD_DIR)/agenticos.img
REPORT_FILE := $(BUILD_DIR)/report.txt

COMMON_OBJS := $(BUILD_DIR)/util.o

PDS := inputd taskd mediator keyring inferd netproxy tool_mail tool_pay agent0 agent1
ELFS := $(addprefix $(BUILD_DIR)/, $(addsuffix .elf, $(PDS)))

.PHONY: all clean run run-live check
all: $(IMAGE_FILE)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/util.o: src/lib/util.c | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/inputd.o:    src/inputd/inputd.c       | $(BUILD_DIR) ; $(CC) -c $(CFLAGS) $< -o $@
$(BUILD_DIR)/taskd.o:     src/taskd/taskd.c         | $(BUILD_DIR) ; $(CC) -c $(CFLAGS) $< -o $@
$(BUILD_DIR)/mediator.o:  src/mediator/mediator.c   | $(BUILD_DIR) ; $(CC) -c $(CFLAGS) $< -o $@
$(BUILD_DIR)/keyring.o:   src/keyring/keyring.c     | $(BUILD_DIR) ; $(CC) -c $(CFLAGS) $< -o $@
$(BUILD_DIR)/inferd.o:    src/inferd/inferd.c       | $(BUILD_DIR) ; $(CC) -c $(CFLAGS) $< -o $@
$(BUILD_DIR)/netproxy.o:  src/netproxy/netproxy.c   | $(BUILD_DIR) ; $(CC) -c $(CFLAGS) $< -o $@
$(BUILD_DIR)/netbackend.o: src/netproxy/backend_$(NET_BACKEND).c | $(BUILD_DIR) ; $(CC) -c $(CFLAGS) $< -o $@
$(BUILD_DIR)/tool_mail.o: src/tools/tool_mail.c     | $(BUILD_DIR) ; $(CC) -c $(CFLAGS) $< -o $@
$(BUILD_DIR)/tool_pay.o:  src/tools/tool_pay.c      | $(BUILD_DIR) ; $(CC) -c $(CFLAGS) $< -o $@
$(BUILD_DIR)/agent0.o:    src/agent/agent.c         | $(BUILD_DIR) ; $(CC) -c $(CFLAGS) -DAGENT_TASK_ID=0 $< -o $@
$(BUILD_DIR)/agent1.o:    src/agent/agent.c         | $(BUILD_DIR) ; $(CC) -c $(CFLAGS) -DAGENT_TASK_ID=1 $< -o $@

$(BUILD_DIR)/netproxy.elf: $(BUILD_DIR)/netproxy.o $(BUILD_DIR)/netbackend.o $(COMMON_OBJS)
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(BUILD_DIR)/%.elf: $(BUILD_DIR)/%.o $(COMMON_OBJS)
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(IMAGE_FILE) $(REPORT_FILE): $(ELFS) $(SYSTEM_FILE)
	$(MICROKIT_TOOL) $(SYSTEM_FILE) --search-path $(BUILD_DIR) \
		--board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) \
		-o $(IMAGE_FILE) -r $(REPORT_FILE)

run: $(IMAGE_FILE)
	qemu-system-aarch64 -machine virt,virtualization=on -cpu cortex-a53 \
		-serial mon:stdio -device loader,file=$(IMAGE_FILE),addr=0x70000000,cpu-num=0 \
		-m size=2G -nographic

# The live backend needs a bridge on the host; see tools/inference-bridge.py.
run-live: $(IMAGE_FILE)
	qemu-system-aarch64 -machine virt,virtualization=on -cpu cortex-a53 \
		-serial mon:stdio -device loader,file=$(IMAGE_FILE),addr=0x70000000,cpu-num=0 \
		-m size=2G -nographic \
		-device virtio-serial-device \
		-chardev socket,path=$(INFER_SOCK),id=infer \
		-device virtconsole,chardev=infer

check: $(IMAGE_FILE)
	scripts/run-scenarios.sh

clean:
	rm -rf $(BUILD_DIR)
