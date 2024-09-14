use std::{
    path::PathBuf,
    collections::{
        HashSet,
        hash_map::DefaultHasher,
    },
    hash::Hasher,
};


use libafl_bolts::{
    Named,
    tuples::{
        tuple_list,
    },
    current_nanos,
    rands::StdRand,
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
        Feedback,
    },
    inputs::{
        BytesInput,
        UsesInput,
    },
    observers::{
        stdio::StdErrObserver,
        ObserversTuple,
    },
    executors::{
        command::CommandExecutor,
        ExitKind,
    },
    //monitors::tui::TuiMonitor,
    monitors::SimpleMonitor,
    mutators::scheduled::{
        StdScheduledMutator,
        havoc_mutations,
    },
    stages::mutational::StdMutationalStage,
    state::{
        StdState,
        
        MaybeHasClientPerfMonitor,
    },
    events::{
        simple::SimpleEventManager,
        EventFirer,
    },
    schedulers::RandScheduler,
};


// Our Custom Feedback based on stdout
// You can add members here for tracking state to be used in your is_interesting function
#[derive(Clone, Debug)]
struct NewOutputFeedback {
    name: String,
    observer_name: String,
}

impl NewOutputFeedback {
    fn new(name: &str, observer_name: &str) -> Self {
        // return a new NewOutputFeedback
        // make sure to instantiate any items you add to the struct here
        Self {
            name: name.to_string(),
            observer_name: observer_name.to_string(),
        }
    }
}

impl<S> Feedback<S> for NewOutputFeedback
where
    S: UsesInput + MaybeHasClientPerfMonitor + libafl::state:State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind
    ) -> Result<bool, Error>
       where EM: EventFirer<State = S>,
             OT: ObserversTuple<S>
    {
        // here we implement is_interesting
        // we grab output from StdErr and see if it is not before seen 
        // our fuzzer will take note of inputs that gave new output on stderr
        // and will further iterate on these inputs
        let observer = observers.match_name::<StdErrObserver>(&self.observer_name)
            .expect("A NewOutputFeedback needs a StdErrObserver");

        /*
            TODO
            Using the output from the StdErrObserver
            determine if we have observed something new
            see:
            https://docs.rs/libafl/latest/libafl/observers/stdio/struct.StdErrObserver.html

            refer to other implementations of the trait Feedback for examples:
            https://docs.rs/libafl/latest/libafl/feedbacks/trait.Feedback.html#implementors

            return Ok(false) for uninteresting inputs
            return Ok(true) for interesting inputs
        */
        
        Ok(false)

    }
}

impl Named for NewOutputFeedback {
    fn name(&self) -> &str {
        &self.name
    }
}

fn main() {
    env_logger::init();

    // we can use the stdout provided by the program to know when we reach new points
    // we use a custom feedback for this, supplied observations by a StdErrObserver
    let observer = StdErrObserver::new("stderr_ob".to_string());
    let mut feedback = NewOutputFeedback::new("stderr_feedback", observer.name());

    // a win will still be any crash we can get
    let mut objective = CrashFeedback::new();

    // simple monitor and event manager to print out our progress
    let monitor = SimpleMonitor::new( |s| println!("{s}") );
    let mut mgr = SimpleEventManager::new(monitor);

    // still just executing a subprocess
    // this time using the target build that prints logs to stderr
    let mut executor = CommandExecutor::builder()
        .program("../fuzz_target/target_dbg")
        .build(tuple_list!(observer))
        .unwrap();

    // our state
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap(),
        &mut feedback,
        &mut objective,
    ).unwrap();


    // keep our normal mutation stage
    let mutator = StdScheduledMutator::with_max_stack_pow(
        havoc_mutations(),
        9,                                                      // maximum mutation iterations
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // randomly schedule from our inputs
    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    // load the initial corpus in our state
    // we have feedback now, so we dont have to use _forced anymore
    // as long as our feedback can tell what inputs are interesting
    state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("../fuzz_target/corpus/")]).unwrap();

    // fuzz
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzz loop");

}
