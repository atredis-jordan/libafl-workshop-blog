use std::{
    path::PathBuf,
};

use libafl_bolts::{
    Named,
    tuples::{
        tuple_list,
    },
    current_nanos,
    rands::StdRand,
    rands::Rand,
    AsMutSlice,
    shmem::{
        ShMem,
        ShMemProvider,
        UnixShMemProvider,
    },
};

use libafl::{
    Error,
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
        HasBytesVec,
    },
    executors::{
        forkserver::ForkserverExecutor,
    },
    monitors::SimpleMonitor,
    mutators::{
        scheduled::{
            StdScheduledMutator,
        },
        mutations::{
            BytesInsertMutator,
            BytesDeleteMutator,
        },
        MutationResult,
        Mutator,
    },
    stages::mutational::StdMutationalStage,
    state::{
        StdState,
        HasRand,
    },
    events::simple::SimpleEventManager,
    schedulers::QueueScheduler,
    observers::{
        HitcountsMapObserver,
        StdMapObserver,
    },
};

// This is our structure that will implement Mutator
// add any needed members here
struct AlphaByteSwapMutator {
}

impl<I, S> Mutator<I, S> for AlphaByteSwapMutator
where
    I: HasBytesVec,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // here we apply our random mutation

        /*
            TODO

            Given the input, mutate it in a smart way for our target

            Our input for this implements HasBytesVec
            so you can use input.bytes_mut() to get a mutable vector

            See other implementors of Mutate for examples in the repo
            https://docs.rs/libafl/latest/libafl/mutators/trait.Mutator.html#implementors

            You can use state.rand_mut() to access a source of random
            https://docs.rs/libafl_bolts/0.11.1/libafl_bolts/rands/trait.Rand.html

            return Ok(MutationResult::Mutated) when you mutate the input
            or Ok(MutationResult::Skipped) when you don't
        */

        Ok(MutationResult::Skipped)
    }
}

impl Named for AlphaByteSwapMutator {
    fn name(&self) -> &str {
        "AlphaByteSwapMutator"
    }
}

impl AlphaByteSwapMutator {
    fn new() -> Self {
        // Add any initialization of our mutator needed here
        Self {
        }
    }
}

fn main() {
    const MAP_SIZE: usize = 65536;

    env_logger::init();

    // this will be the same as the aflcc fuzzer
    // except we will specify a custom mutator

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

    // use a forkserver
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

    // we will specify our custom mutator, as well as two other helpful mutators for growing or shrinking
    let mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            AlphaByteSwapMutator::new(),
            BytesDeleteMutator::new(),
            BytesInsertMutator::new(),
        ),
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
