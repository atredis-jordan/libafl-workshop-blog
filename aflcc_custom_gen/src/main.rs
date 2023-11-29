
use std::{
    env,
    path::PathBuf,
};

use libafl_bolts::{
    tuples::{
        tuple_list,
    },
    current_nanos,
    rands::StdRand,
};

use libafl::{
    corpus::{
        inmemory::InMemoryCorpus,
        ondisk::OnDiskCorpus,
    },
    executors::{
        inprocess::InProcessExecutor,
            ExitKind,
    },
    generators::{
        nautilus::{
            NautilusContext, NautilusGenerator,
        },
        Generator,
    },
    fuzzer::{
        StdFuzzer,
        Fuzzer,
    },
    feedbacks::{
        nautilus::NautilusChunksMetadata,
        MaxMapFeedback,
        CrashFeedback,
    },
    inputs::{
        nautilus::NautilusInput,
    },
    events::llmp::setup_restarting_mgr_std,
    monitors::MultiMonitor,
    mutators::{
        NautilusRandomMutator, NautilusRecursionMutator, NautilusSpliceMutator,
        scheduled::StdScheduledMutator,
    },
    stages::mutational::StdMutationalStage,
    state::{
        StdState,
        HasMetadata,
    },
    events::{
        EventConfig,
    },
    schedulers::QueueScheduler,
};

use libafl_targets::{
    libfuzzer_initialize,
    libfuzzer_test_one_input,
    std_edges_map_observer,
};


fn main() {
    // we still use an in process executor
    // but this time instead of pulling in a corpus, we will generate input trees based on a grammar
    // and mutate on trees, evaluating them before passing them to the target function

    // we use a multimonitor to collect all the events across mutliple processes
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    println!("Starting up");

    env_logger::init();

    // we use a restarting manager
    let (state, mut restarting_mgr) = setup_restarting_mgr_std(monitor, 1337, EventConfig::from_name("default"))
        .expect("Failed to setup the restarter!");

    println!("We are a client!");

    // observe
    let edges_observer = unsafe { std_edges_map_observer("edges") };
    let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

    // use normal crashing objective
    let mut objective = CrashFeedback::new();

    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryCorpus::new(), // test cases in memory for much fastness
            OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap(),
            &mut feedback,
            &mut objective,
        ).unwrap()
    });


    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // create a grammar context for our generation and mutation
    // this contains the information parsed from our grammar definition
    let tree_depth = 0x45;
    let genctx = NautilusContext::from_file(tree_depth, "./grammar.json");

    if state.metadata_map().get::<NautilusChunksMetadata>().is_none() {
        // add some metadata for our state for gen
        state.add_metadata(NautilusChunksMetadata::new("/tmp/".into()));
    }

    let mut bytes = vec![];

    // our executor will be just a wrapper around a harness closure
    let mut harness = |input: &NautilusInput| {
        // we need to convert our input from a natilus tree
        // into actual bytes
        input.unparse(&genctx, &mut bytes);

        //let s = std::str::from_utf8(&bytes).unwrap();
        //println!("Trying:\n{:?}", s);

        let buf = bytes.as_mut_slice();

        libfuzzer_test_one_input(&buf);

        return ExitKind::Ok;
    };

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut restarting_mgr,
    ).unwrap();

    // initialize the libfuzzer stuff (if there is an init)
    let args: Vec<String> = env::args().collect();
    if libfuzzer_initialize(&args) < 0 {
        // shouldn't happen
        println!("WARN: Libfuzzer init failed!")
    }


    if state.must_load_initial_inputs() {
        // instead of loading from an inital corpus, we will generate our initial corpus of 9 nautilus trees
        let mut generator = NautilusGenerator::new(&genctx);
        state.generate_initial_inputs_forced(&mut fuzzer, &mut executor, &mut generator, &mut restarting_mgr, 9).unwrap();
        println!("Created initial inputs");

        // we can test our grammar generator here a bit
        // notice that we need a sufficient tree_depth in our context
        // in order to really exercise the tree here
        /*
        let mut b = vec![];
        for _ in 0..10 {
            let i = generator.generate(&mut state).unwrap();
            i.unparse(&genctx, &mut b);
            let s = std::str::from_utf8(&b).unwrap();
            println!("Generated:\n{:?}", s);
        }
        */
    }

    // set up mutation
    // we can't use normal byte mutations, so we use mutations that work on our generator trees
    let mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            NautilusRandomMutator::new(&genctx),
            NautilusRandomMutator::new(&genctx),
            NautilusRandomMutator::new(&genctx),
            NautilusRecursionMutator::new(&genctx),
            NautilusSpliceMutator::new(&genctx),
            NautilusSpliceMutator::new(&genctx),
        ),
        3,
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // run it
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr).unwrap();
}
