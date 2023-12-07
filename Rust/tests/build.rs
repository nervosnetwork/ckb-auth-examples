use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../ckb-auth");

    let ckb_auth_dir = PathBuf::from("../../deps/ckb-auth");

    let make_result = Command::new("make")
        .arg("all-via-docker")
        .current_dir(&ckb_auth_dir)
        .status()
        .expect("failed to execute make");

    // // 检查 make 命令的执行结果
    if make_result.success() {
        println!("make all success");
    } else {
        panic!("make all failed");
    }

    let ckb_auth_build_dir = ckb_auth_dir.join("build");

    // copy to build
    std::fs::copy(ckb_auth_build_dir.join("auth"), "../build/auth").expect("copy ckb-auth");
    std::fs::copy(ckb_auth_build_dir.join("secp256k1_data_20210801"), "../build/secp256k1_data_20210801")
        .expect("copy secp256k1_data_20210801");
}
