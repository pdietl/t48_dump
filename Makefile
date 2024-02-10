MAKEFILE_PATH     := $(abspath $(lastword $(MAKEFILE_LIST)))
MAKEFILE_DIR      := $(dir $(MAKEFILE_PATH))
DOCKER_IMAGE_NAME := ghcr.io/pdietl/t48-dump:2

# Docker things

DOCKER_CMD := \
	docker run -ti --rm \
		-u $(shell id -u):$(shell id -g) \
		-v /etc/group:/etc/group:ro \
		-v /etc/passwd:/etc/passwd:ro \
		-v '$(MAKEFILE_DIR):$(MAKEFILE_DIR)' \
		-w '$(MAKEFILE_DIR)' \
		$(DOCKER_IMAGE_NAME)

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
	$(DOCKER_CMD) /bin/bash -c -- \
		make $*

.PHONY: clean
clean:
	$(RM) -r out
