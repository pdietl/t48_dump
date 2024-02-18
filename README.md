# t48_dump

This project takes the original t48 bootloader binary and creates `startup.s` and `main.s`
which can produce `out/bootloader.elf` that is bit-for-bit identical to the original binary.
This should facilitate reverse engineering efforts.

## Building

make docker-shell
make
