# ckb-auth-examples
Example projects for ckb-auth: https://github.com/nervosnetwork/ckb-auth


Submodules and their dependencies need to be updated before compilation:
```shell
git submodule update --init --recursive
```

## Rust example

### Install tools
The rust example depends on capsule and cross, Need to install before compiling:

```shell
cargo install ckb-capsule --version "0.10.2"
cargo install cross --git https://github.com/cross-rs/cross
```
* The capsule requires 0.10.2
* The cross requires the main branch (some bugs have been solved, and a new version has not been released yet).

### Build
In directory `Rust`:

```shell
capsule build
```

### Test
In directory `Rust`:

```shell
capsule test
```

`deps/ckb-auth` is compiled in `Rust/tests/build.rs`, and `auth` and `secp256k1_data_20210801` are copied to `Rust/build` for testing.

The tests here only have a few simple cases. More test cases in ckb-auth.


## C example

### Build
In directory C:
```shell
make all-via-docker
# build with GNU toolchain
```

or

```shell
make -f Makefile.clang all
# build with LLVM toolchain
```

The compilation results are in `C/build`. 

If in docker to compile: the docker mapping directory should be this repo, because the code depends on `ckb_auth.h`.


### Test
The contract interfaces of C example and Rust example are same, so C example generally uses rust's tests.
Here, copy the C bin directly to `Rust/build/debug` and rename it to `auth-rust-example`. 

In actual use:
* Copy `Rust/tests` to C language contract directory.
* Modify the name in `src/lib.rs`.
* Copy `auth` and `secp256k1_data_20210801` to `build`.
