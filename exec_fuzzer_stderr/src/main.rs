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
        HasClientPerfMonitor,
    },
    events::{
        simple::SimpleEventManager,
        EventFirer,
    },
    schedulers::RandScheduler,
};


// Our Custom Feedback based on stdout
#[derive(Clone, Debug)]
struct NewOutputFeedback {
    hash_set: HashSet<u64>,
    name: String,
    observer_name: String,
}

impl NewOutputFeedback {
    fn new(name: &str, observer_name: &str) -> Self {
        Self {
            hash_set: HashSet::new(),
            name: name.to_string(),
            observer_name: observer_name.to_string(),
        }
    }
}

impl<S> Feedback<S> for NewOutputFeedback
where
    S: UsesInput + HasClientPerfMonitor,
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


        let mut hasher = DefaultHasher::new();
        hasher.write(&observer.stderr.clone().unwrap());
        let hash = hasher.finish();

        if self.hash_set.contains(&hash) {
            Ok(false)
        } else {
            self.hash_set.insert(hash);
            // we could print the new input to see what kinds of logs are getting us new coverage
            //println!("Stdout: {:?}", std::str::from_utf8(&observer.stderr.clone().unwrap()));
            Ok(true)
        }
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
    // we have feedback now, so we can have it check the feedback
    // and only keep inputs that have unique feedback
    state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("../fuzz_target/corpus/")]).unwrap();

    // fuzz
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzz loop");

}
