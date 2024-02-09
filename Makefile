DOCKER_IMAGE_NAME := t48

MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MAKEFILE_DIR := $(dir $(MAKEFILE_PATH))

DOCKER_CMD := \
	docker run -ti --rm --privileged \
		-u $(shell id -u):$(shell id -g) \
		-v /etc/group:/etc/group:ro \
		-v /etc/passwd:/etc/passwd:ro \
		-v '$(MAKEFILE_DIR):$(MAKEFILE_DIR)' \
		-w '$(MAKEFILE_DIR)' \
		$(DOCKER_IMAGE_NAME)

.PHONY: docker
docker:
	docker build --progress plain . -t $(DOCKER_IMAGE_NAME)

.PHONY: shell
shell:
	$(DOCKER_CMD) /bin/bash

.PHONY: clean
clean:
	$(RM) -r $(BUILD_DIR)

docker-%:
	$(DOCKER_CMD) /bin/bash -c -- \
		make $*
