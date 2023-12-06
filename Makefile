
CI: \
	CI_Rust \
	CI_C_GNU \
	CI_C_LLVM


CI_Rust:
	cd Rust && capsule build
	cd Rust && capsule test

CI_C_GNU:
	cd C && make test

CI_C_LLVM:
	cd C && make -f Makefile.clang test

install_tools:
	cargo install ckb-capsule --version "0.10.2"
	cargo install cross --git https://github.com/cross-rs/cross

clean:
	cd C && make clean
	rm -rf Rust/build
	rm -rf Rust/target
	rm -rf Rust/build
	rm -rf Rust/tests/target

# 	cd Rust && capsule clean 		# capsule cannot be found under sudo
