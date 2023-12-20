CKB_AUTH=../deps/ckb-auth

TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -fPIC -O3 -g \
		-Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function \
		-fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostdlib -nostartfiles \
		-fvisibility=hidden -fdata-sections -ffunction-sections \
		-I $(CKB_AUTH)/deps/secp256k1/src \
		-I $(CKB_AUTH)/deps/secp256k1 \
		-I $(CKB_AUTH)/deps/ckb-c-std-lib \
		-I $(CKB_AUTH)/deps/ckb-c-std-lib/libc \
		-I $(CKB_AUTH)/deps/ckb-c-std-lib/molecule \
		-I $(CKB_AUTH)/c \
		-I $(CKB_AUTH)/build
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
AUTH_CFLAGS=$(subst ckb-c-std-lib,ckb-c-stdlib-2023,$(CFLAGS)) -Wno-dangling-pointer -Wno-array-bounds -Wno-stringop-overflow

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-jammy-20230214
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:d3f649ef8079395eb25a21ceaeb15674f47eaa2d8cc23adc8bcdae3d5abce6ec

all: ckb-auth-all build/auth_c_example

# Because it depends on `../deps/ckb-auth`, the upper-level directory is mapped in docker.
all-via-docker:
	docker run --platform linux/amd64 --rm -v `pwd`/../:/code ${BUILDER_DOCKER} bash -c "cd /code/C && make all"

ckb-auth-all:
	cd $(CKB_AUTH) && make all
	mkdir -p build

build/auth_c_example: auth_c_example.c $(CKB_AUTH)/c/ckb_auth.h
	$(CC) $(AUTH_CFLAGS) $(LDFLAGS) -DCKB_AUTH_DL_BUFF_SIZE=0x96000 -o $@ $^
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

# C's example has the same interface as rust, so here we borrow rust's tests for testing.
test: all-via-docker
	rm -rf ../Rust/build/
	mkdir -p ../Rust/build
	cp $(CKB_AUTH)/build/auth ../Rust/build
	cp $(CKB_AUTH)/build/auth_libecc ../Rust/build
	cp $(CKB_AUTH)/build/secp256k1_data_20210801 ../Rust/build
	mkdir -p ../Rust/build/debug
	cp build/auth_c_example ../Rust/build/debug/auth-rust-example
	cd ../Rust/tests && cargo test

clean:
	rm -rf build/*
	cd $(CKB_AUTH) && make clean
