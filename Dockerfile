# syntax=docker/dockerfile:1

FROM ubuntu:22.04

WORKDIR /root

# Make sh point to bash
RUN ln -sf /bin/bash /bin/sh

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y \
    curl \
    python3 \
    build-essential

# Install the riscv toolchain
RUN touch ~/.bashrc && chmod +x ~/.bashrc

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/master/install.sh | bash

RUN . ~/.nvm/nvm.sh && \
    source ~/.bashrc && \
    nvm install node 21 && \
    nvm alias default 21 && \
    nvm use default && \
    npm install --global xpm@latest && \
    xpm init && \
    xpm install --global @xpack-dev-tools/riscv-none-elf-gcc@13.2.0-2.1 --verbose

RUN cp -r -v ~/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/13.2.0-2.1/.content/* /usr/local && \
    rm -rf ~/.local/xPacks

RUN riscv-none-elf-gcc --version
