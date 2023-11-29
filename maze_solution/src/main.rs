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
        HasBytesVec,
    },
    observers::{
        stdio::StdOutObserver,
        ObserversTuple,
    },
    executors::{
        command::CommandExecutor,
        ExitKind,
    },
    //monitors::tui::TuiMonitor,
    monitors::SimpleMonitor,
    mutators::{
        scheduled::StdScheduledMutator,
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
        HasClientPerfMonitor,
        HasRand,
    },
    events::{
        simple::SimpleEventManager,
        EventFirer,
    },
    schedulers::QueueScheduler,
};

// our custom mutators to just use wasd
struct MazeByteSwapMutator {
}

impl<I, S> Mutator<I, S> for MazeByteSwapMutator
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
        // for our target, simply swapping a byte should be effective
        // so long as our new byte is wasd

        // skip empty inputs
        if input.bytes().is_empty() {
            return Ok(MutationResult::Skipped)
        }

        // choose a random byte
        let byte: &mut u8 = state.rand_mut().choose(input.bytes_mut());

        // now we can replace that byte with was or d
        *byte = *state.rand_mut().choose(b"wasd");
        
        // technically we should say "skipped" if we replaced a byte with itself, but this is fine for now
        Ok(MutationResult::Mutated)
    }
}

impl Named for MazeByteSwapMutator {
    fn name(&self) -> &str {
        "MazeByteSwapMutator"
    }
}

impl MazeByteSwapMutator {
    fn new() -> Self {
        Self {
        }
    }
}

// Our Custom Feedback based on stdout
#[derive(Clone, Debug)]
struct NewMazePathFeedback {
    map: Vec<u8>,
    name: String,
    observer_name: String,
}

impl NewMazePathFeedback {
    fn new(name: &str, observer_name: &str) -> Self {
        Self {
            map: Vec::new(),
            name: name.to_string(),
            observer_name: observer_name.to_string(),
        }
    }
}

impl<S> Feedback<S> for NewMazePathFeedback
where
    S: UsesInput + HasClientPerfMonitor,
    S::Input: HasBytesVec,
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
        let observer = observers.match_name::<StdOutObserver>(&self.observer_name)
            .expect("A NewOutputFeedback needs a StdOutObserver");
    
        // we are only interested in an output that gets us farther in the maze
        // let's keep a map of the empty maze, and mark off empty spaces as we go
        // we will just care about the final frame of the output

        let mut out = observer.stdout.clone().unwrap();
        out.reverse();

        // find from line of all '#' to another
        // except the first will start with '\n  '
        let mut start = -1;
        let mut end = -1;
        let mut couldbe = -1;
        let mut seenhash = false;

        for (i, v) in out.iter().enumerate() {
            if couldbe != -1 {
                if *v == b'#' {
                    seenhash = true;
                    continue;
                }
                else if !seenhash && *v == b' ' {
                    continue;
                }
                else if *v == b'\n' {
                    // found the line!
                    if start == -1 {
                        start = couldbe;
                        couldbe = -1;
                        continue;
                    } else {
                        end = couldbe;
                        break;
                    }
                }
                else {
                    couldbe = -1;
                }
            }
            
            if *v == b'\n' {
                couldbe = i as i32;
                seenhash = false;
            }
        }

        if start <= -1 || end <= -1 {
            println!("Debug: Strange maze, couldn't find start and end");
            return Ok(false);
        }

        let start = start as usize;
        let end = end as usize;

        let out = &out[start..end];

        if self.map.len() == 0 {
            self.map.resize(end - start, 0);
        }

        // then for each '.' , check if that spot is set in our map yet
        // if it isn't, mark it and report this as interesting
        for (i, v) in out.iter().enumerate() {
            if i >= self.map.len() {
                //let outstr = std::str::from_utf8(&out).unwrap();
                //println!("Big maze?:\n{outstr}");
                //let instr = std::str::from_utf8(&_input.bytes()).unwrap();
                //println!("Input:\n{}", instr);
                
                // it looks like if there are too many newlines in the input, we start getting weird because of all the output
                // we maybe hit some maximum size the stdout captures?
                // so make sure the corpus doesn't have any newlines
                // if it has newlines, then the insert mutator will add more
                panic!("Index out of bounds! {i} >= {}", self.map.len());
            }
            if *v == b'.' {
                if self.map[i] == 0 {
                    self.map[i] = 1;
                    // debug
                    let outstr = std::str::from_utf8(&out).unwrap();
                    println!("Found:\n{outstr}");

                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

impl Named for NewMazePathFeedback {
    fn name(&self) -> &str {
        &self.name
    }
}

fn main() {
    env_logger::init();

    let observer = StdOutObserver::new("stdout_ob".to_string());
    let mut feedback = NewMazePathFeedback::new(
        "stdout_feedback",
        observer.name(),
    );

    let mut objective = CrashFeedback::new();

    let monitor = SimpleMonitor::new( |s| println!("{s}") );
    let mut mgr = SimpleEventManager::new(monitor);

    let mut executor = CommandExecutor::builder()
        .program("../maze_target/maze")
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


    // use special mutations to only add or replace wasd\n
    //TODO
    let mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            MazeByteSwapMutator::new(),
            MazeByteSwapMutator::new(),
            MazeByteSwapMutator::new(),
            BytesInsertMutator::new(),
            BytesInsertMutator::new(),
            BytesDeleteMutator::new(),
        ),
        9,                                                      // maximum mutation iterations
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // To increase our speed would could prioritize scheduling inputs that reach father in the maze
    // but for now, just queue them normally
    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    // load the initial corpus in our state
    state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from("./corpus/")]).unwrap();

    // fuzz
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzz loop");

}
