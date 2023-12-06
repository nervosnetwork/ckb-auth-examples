
CI: \
	CI_Rust \
	CI_C_GNU \
	clean \
	CI_C_LLVM


CI_Rust:
	cd Rust && capsule test

CI_C_GNU:
	cd C && make test

CI_C_LLVM:
	cd C && make -f Makefile.clang test

# The rust example needs to be compiled using cpasule and cross. Both of these can be installed using ckb-auth/tests/Makefile
install_tools:
	cd deps/ckb-auth/tests/ && make install-capsule
	cd deps/ckb-auth/tests/ && make install-cross

clean:
	cd C && make clean
	cd Rust && capsule clean
	rm -rf Rust/build
	rm -rf Rust/tests/target
