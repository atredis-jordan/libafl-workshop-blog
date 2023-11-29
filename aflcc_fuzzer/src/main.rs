use std::{
    path::PathBuf,
};

use libafl_bolts::{
    tuples::{
        tuple_list,
    },
    current_nanos,
    rands::StdRand,
    AsMutSlice,
    shmem::{
        ShMem,
        ShMemProvider,
        UnixShMemProvider,
    },
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
        MaxMapFeedback,
    },
    inputs::{
        BytesInput,
    },
    executors::{
        forkserver::ForkserverExecutor,
    },
    monitors::SimpleMonitor,
    mutators::{
        scheduled::{
            StdScheduledMutator,
            havoc_mutations,
        },
    },
    stages::mutational::StdMutationalStage,
    state::{
        StdState,
    },
    events::simple::SimpleEventManager,
    schedulers::QueueScheduler,
    observers::{
        HitcountsMapObserver,
        StdMapObserver,
    },
};


fn main() {
    const MAP_SIZE: usize = 65536;

    env_logger::init();

    // This time we are going to have feedback based on the compiled in instrumentation
    // we need a MaxMapFeedback, which reads from the map from a HitcountsMapObserver
    // this will use shared memory in the target process for accessing the map

    // first allocate shared memory
    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // write the id to the env var for the forkserver
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmembuf = shmem.as_mut_slice();
    // build an observer based on that buffer shared with the target
    let edges_observer = unsafe {HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmembuf))};
    // use that observed coverage to feedback based on obtaining maximum coverage
    let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

    // win on an crash
    let mut objective = CrashFeedback::new();

    let monitor = SimpleMonitor::new( |s| println!("{s}") );
    let mut mgr = SimpleEventManager::new(monitor);

    // This time we can use a forkserver executor, which uses a instrumented in fork server
    // it gets a greater number of execs per sec by not having to init the process for each run
    let mut executor = ForkserverExecutor::builder()
        .program("../fuzz_target/target_instrumented")
        .shmem_provider(&mut shmem_provider)
        .coverage_map_size(MAP_SIZE)
        .build(tuple_list!(edges_observer))
        .unwrap();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap(),
        &mut feedback,
        &mut objective,
    ).unwrap();

    // here we could merge in tokens_mutations(), since the afl-cc can set up autodict
    let mutator = StdScheduledMutator::with_max_stack_pow(
        havoc_mutations(),
        9,
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    // load the initial corpus in our state
    // we can let it gather feedback about what inputs are useful or not now
    state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("../fuzz_target/corpus/")]).unwrap();

    // fuzz
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzz loop");

}
