use std::{
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
    fuzzer::{
        StdFuzzer,
        Fuzzer,
    },
    feedbacks::{
        CrashFeedback,
        ConstFeedback,
    },
    inputs::{
        BytesInput,
    },
    executors::{
        command::CommandExecutor,
    },
    monitors::SimpleMonitor,
    mutators::scheduled::{
        StdScheduledMutator,
        havoc_mutations,
    },
    stages::mutational::StdMutationalStage,
    state::{
        StdState,
    },
    events::simple::SimpleEventManager,
    schedulers::RandScheduler,
};

fn main() {
    // this let's us see LibAFL internal logs for better debugging info
    // just use RUST_LOG=debug or whatever
    env_logger::init();

    // we don't have any instrumentation in here to tell us when we find a new path
    // so we just have no feedback
    let mut feedback = ConstFeedback::False;

    // Our "objective" is a feedback that tells our fuzzer when we have a win!
    // we could include timeouts, certain outputs, created files, etc
    // here we will just win when our target crashes
    let mut objective = CrashFeedback::new();

    // we need to make our monitor
    // this is just to report stats back to our screen
    // libafl includes some nicer ways to show this too, like the TuiMonitor
    let monitor = SimpleMonitor::new( |s| println!("{s}") );
    // the event manager takes in events/stats during the fuzzer
    // here we could programatically respond to those events
    // but we will just use a manager that sends the events on to the monitor
    let mut mgr = SimpleEventManager::new(monitor);

    // we need to make our executor
    // this defines how we execute each test case
    // this could be using qemu, frida, or using a forkserver compiled in
    // we will just use the most simple "CommandExecutor" which runs a child process
    // by default it will use stdin to send over the input, unless we specify otherwise
    let mut executor = CommandExecutor::builder()
        .program("../fuzz_target/target")
        .build(tuple_list!())
        .unwrap();

    // we need a state to hold our fuzzing state
    // a state tracks our corpora (inputs and solutions)
    // and other metadata
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap(),
        &mut feedback,
        &mut objective,
    ).unwrap();


    // We need to make our stages
    // these will be executed in order for each new executed testcase
    // All we need are normal byte mutations for now
    // But here we could also have tracing stages,
    // calibration, generation, sync stages, etc
    // see implementations of the Stage trait in LibAFL
    let mutator = StdScheduledMutator::with_max_stack_pow(
        havoc_mutations(),
        9,                                                      // maximum mutation iterations
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // we need a scheduler for our fuzzer to choose how to schedule inputs in our corpus
    let scheduler = RandScheduler::new();
    // now we can build our fuzzer
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    // load the initial corpus in our state
    // since we lack feedback, we have to force this,
    // otherwise it will only load inputs it deems interesting
    // which will result in an empty corpus for us
    state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("../fuzz_target/corpus/")]).unwrap();

    // fuzz
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzz loop");

}
