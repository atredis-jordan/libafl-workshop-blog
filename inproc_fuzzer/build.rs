// build.rs

fn main() {
    // in build.rs we can output arguments to our build toolset
    // which allows us to link with our target library

    let target_dir = "../fuzz_target".to_string();
    let target_lib = "target_libfuzzer".to_string();

    println!("cargo:rustc-link-search=native={}", &target_dir);
    // whole archive is needed here to make sure the symbols get loaded
    // note that building with afl_cc is going to be better if you can, because
    // it will take care of lots of this for you
    // see libafl/fuzzers/fuzzbench/src/bin/libafl_cc.rs
    // but this is an example of how to link a built static library for fuzzing
    println!("cargo:rustc-link-lib=static:+whole-archive={}", &target_lib);

    println!("cargo:rerun-if-changed=build.rs");
}
