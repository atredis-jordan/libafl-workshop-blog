
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
    AsSlice,
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
    fuzzer::{
        StdFuzzer,
        Fuzzer,
    },
    feedbacks::{
        MaxMapFeedback,
        CrashFeedback,
    },
    inputs::{
        BytesInput,
        HasTargetBytes,
    },
    events::llmp::setup_restarting_mgr_std,
    monitors::MultiMonitor,
    mutators::scheduled::{
        StdScheduledMutator,
        havoc_mutations,
    },
    stages::mutational::StdMutationalStage,
    state::{
        StdState,
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
    // here we will do "in process" fuzzing
    // where our binary is linked with the target code to be fuzzed
    // this allows us to go real fast
    // see build.rs to see how we link ourselves with the compiled c code
    // which we compiled as a library
    // we could also have compiled libafl as the library, we can be flexible

    // we use a multimonitor to collect all the events across mutliple processes
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    println!("Starting up");

    env_logger::init();

    // we use a restarting manager which will restart
    // our process each time it crashes
    // this will set up a host manager, and we will have to start the other processes
    let (state, mut restarting_mgr) = setup_restarting_mgr_std(monitor, 1337, EventConfig::from_name("default"))
        .expect("Failed to setup the restarter!");

    // only clients will return from the above call
    println!("We are a client!");

    // observe
    // we have to use unsafe because edges is a shared memory region in our process
    let edges_observer = unsafe { std_edges_map_observer("edges") };
    let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

    // use normal crashing objective
    let mut objective = CrashFeedback::new();

    // if we are restarting, the setup_restarting_mgr_std will have given us a state
    // otherwise we make a new one in the closure

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

    // our executor will be just a wrapper around a harness
    // that calls out the the libfuzzer style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        // this is just some niceness to call the libfuzzer C function
        // but we don't need to use a libfuzzer harness to do inproc fuzzing
        // we can call whatever function we want in a harness, as long as it is linked
        libfuzzer_test_one_input(buf);
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
        state.load_initial_inputs(&mut fuzzer, &mut executor, &mut restarting_mgr, &[PathBuf::from("../fuzz_target/corpus/")]).unwrap();
        println!("Loaded initial inputs")
    }

    // set up mutation
    let mutator = StdScheduledMutator::with_max_stack_pow(
        havoc_mutations(),
        9,
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // run it
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr).unwrap();
}
