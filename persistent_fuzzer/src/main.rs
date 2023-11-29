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
    observers::{
        HitcountsMapObserver,
        StdMapObserver,
    },
};


fn main() {
    const MAP_SIZE: usize = 65536;

    env_logger::init();

    // Like the other targets with compiled in instrumentation, we use shared memory to access the maps
    // also, forkserver executor will know how to negotiate with the compiled in forkserver to use
    // the shared memory for handing over testcases

    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmembuf = shmem.as_mut_slice();
    let edges_observer = unsafe {HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmembuf))};
    let mut feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

    let mut objective = CrashFeedback::new();

    let monitor = SimpleMonitor::new( |s| println!("{s}") );
    let mut mgr = SimpleEventManager::new(monitor);

    // Almost everything is the same as last time, but now we tell the forkserver about our shmem
    // provider, and that we want to run persistant
    // Also, we had to make a few changes to our target so that the shmem testcases work
    let mut executor = ForkserverExecutor::builder()
        .program("../fuzz_target/target_persistent")
        .is_persistent(true)
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

    let mutator = StdScheduledMutator::with_max_stack_pow(
        havoc_mutations(),
        9,
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("../fuzz_target/corpus/")]).unwrap();

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzz loop");
}
