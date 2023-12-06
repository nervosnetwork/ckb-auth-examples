TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -fPIC -O3 -g \
		-Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function \
		-fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostdlib -nostartfiles \
		-fvisibility=hidden -fdata-sections -ffunction-sections \
		-I ckb-auth/deps/secp256k1/src \
		-I ckb-auth/deps/secp256k1 \
		-I ckb-auth/deps/ckb-c-std-lib \
		-I ckb-auth/deps/ckb-c-std-lib/libc \
		-I ckb-auth/deps/ckb-c-std-lib/molecule \
		-I ckb-auth/c \
		-I ckb-auth/build
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
AUTH_CFLAGS=$(subst ckb-c-std-lib,ckb-c-stdlib-2023,$(CFLAGS)) -Wno-dangling-pointer -Wno-array-bounds -Wno-stringop-overflow

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-jammy-20230214
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:d3f649ef8079395eb25a21ceaeb15674f47eaa2d8cc23adc8bcdae3d5abce6ec

all: ckb-auth-all build/auth_c_example

all-via-docker:
	docker run --platform linux/amd64 --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make all"

ckb-auth-all:
	mkdir -p build
	cd ckb-auth && make all
	cp ckb-auth/build/auth build/
	cp ckb-auth/build/secp256k1_data_20210801 build/

ckb-auth-all-via-docker:
	mkdir -p build
	cd ckb-auth && make all-via-docker
	cp ckb-auth/build/auth build/
	cp ckb-auth/build/secp256k1_data_20210801 build/

build/auth_c_example: auth_c_example.c ckb-auth/c/ckb_auth.h
	$(CC) $(AUTH_CFLAGS) $(LDFLAGS) -o $@ $^
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

clean:
	rm -rf build/*
	cd ckb-auth && make clean
