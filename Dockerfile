# syntax=docker/dockerfile:1

FROM ubuntu:22.04 AS base

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y \
    build-essential \
    curl \
    git \
    python3 \
    python3-poetry

FROM base AS poetry_dep_install
ADD pyproject.toml poetry.lock /poetry/
RUN cd /poetry && poetry export --without-hashes --format=requirements.txt > requirements.txt

FROM base

WORKDIR /root

# Make sh point to bash
RUN ln -sf /bin/bash /bin/sh

# Install the riscv toolchain
RUN touch ~/.bashrc && chmod +x ~/.bashrc

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/master/install.sh | bash

RUN . ~/.nvm/nvm.sh && \
    source ~/.bashrc && \
    nvm install node 21 && \
    nvm alias default 21 && \
    nvm use default && \
    npm install --global xpm@latest

RUN . ~/.nvm/nvm.sh && \
    xpm init && \
    xpm install --global @xpack-dev-tools/riscv-none-elf-gcc@13.2.0-2.1 && \
    cp -r -v ~/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/13.2.0-2.1/.content/* /usr/local && \
    rm -rf ~/.local/xPacks && \
    riscv-none-elf-gcc --version

RUN --mount=type=bind,from=poetry_dep_install,source=/poetry,target=/poetry cd /poetry && pip install -r requirements.txt
