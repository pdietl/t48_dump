MAKEFILE_PATH     := $(abspath $(lastword $(MAKEFILE_LIST)))
MAKEFILE_DIR      := $(dir $(MAKEFILE_PATH))
MAKEFILE_DIR      := $(MAKEFILE_DIR:/=)
DOCKER_IMAGE_NAME := ghcr.io/pdietl/t48-dump:3

DOCKER_CMD := \
	docker run -ti --rm \
		-u $(shell id -u):$(shell id -g) \
		-v $(HOME)/.cache:$(HOME)/.cache \
		-v /etc/group:/etc/group:ro \
		-v /etc/passwd:/etc/passwd:ro \
		-v '$(MAKEFILE_DIR):$(MAKEFILE_DIR)' \
		-w '$(MAKEFILE_DIR)' \
		$(DOCKER_IMAGE_NAME)

SHELL   := /bin/bash
CROSS   := riscv-none-elf-
LD      := $(CROSS)ld
AS      := $(CROSS)as
ASFLAGS := -march=rv32gc -mabi=ilp32f
B       := $(MAKEFILE_DIR)/out

VPATH := $(MAKEFILE_DIR)/out

$(B)/bootloader.elf: link.ld $(B)/startup.o $(B)/main.o
	$(LD) -o $@ -T $^

%.o: %.s
	$(AS) -o $@ $(ASFLAGS) $^ -a=$@.list

$(B)/startup.s $(B)/main.s&: make_elf.py
	./$<

### Docker targets ###

# Build the Docker image
.PHONY: docker-build
docker-build:
	docker build . -t $(DOCKER_IMAGE_NAME)

# Push the Docker image to Github Container Repository
.PHONY: docker-push
docker-push:
	docker push $(DOCKER_IMAGE_NAME)

# Enter a bash shell in the Docker container
.PHONY: docker-shell
docker-shell:
	$(DOCKER_CMD) /bin/bash

# Run any other Makefile target within the Docker container
docker-%:
	$(DOCKER_CMD) /bin/bash -c -- make $*

### Other targets ###

.PHONY: clean
clean:
	$(RM) -r out
