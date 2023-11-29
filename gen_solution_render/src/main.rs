
use std::{
    path::PathBuf,
    env,
};

use libafl::{
    inputs::{
        nautilus::NautilusInput,
        Input,
    },
    generators::{
        nautilus::{
            NautilusContext, NautilusGenerator,
        },
        Generator,
    },
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Please provide path to the NautilusInput file");
        return;
    }

    let grammarpath = if args.len() > 2 {
        &args[2]
    } else {
        "../aflcc_custom_gen/grammar.json"
    };

    let path = PathBuf::from(&args[1]);

    let input: NautilusInput = NautilusInput::from_file(path).unwrap();
    let mut b = vec![];

    let tree_depth = 0x45;
    let genctx = NautilusContext::from_file(tree_depth, grammarpath);

    input.unparse(&genctx, &mut b);

    let s = std::str::from_utf8(&b).unwrap();
    println!("{s}");
}
