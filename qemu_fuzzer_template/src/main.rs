
use std::{
    env,
    path::PathBuf,
    ptr::addr_of_mut,
};


use libafl_bolts::{
    Named,
    tuples::{
        tuple_list,
    },
    shmem::{ShMemProvider, StdShMemProvider},
    current_nanos,
    rands::StdRand,
    rands::Rand,
    AsSlice,
};

use libafl::{
    corpus::{
        inmemory::InMemoryCorpus,
        ondisk::OnDiskCorpus,
    },
    executors::{
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
        HasBytesVec,
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
    observers::map::{
        HitcountsMapObserver,
        VariableMapObserver,
    },
    state::{
        StdState,
        HasRand,

    },
    events::{
        SimpleRestartingEventManager,
    },
    schedulers::QueueScheduler,
    Error,
};

use libafl_qemu::{
    edges::{
        edges_map_mut_slice,
        QemuEdgeCoverageHelper,
        MAX_EDGES_NUM,
    },
    elf::EasyElf,
    emu::Emulator,
    hooks::QemuHooks,
    GuestReg,
    GuestAddr,
    MmapPerms,
    QemuExecutor,
    Regs,
    ArchExtras,
};

struct AlphaByteSwapMutator {
    good_bytes: Vec<u8>,
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
        // for our target, simply swapping a byte should be effective
        // so long as our new byte is 0-9A-Za-z or '-' or '_'

        // skip empty inputs
        if input.bytes().is_empty() {
            return Ok(MutationResult::Skipped)
        }

        // choose a random byte
        let byte: &mut u8 = state.rand_mut().choose(input.bytes_mut());
        
        // now we can replace that byte with a known good byte
        *byte = *state.rand_mut().choose(&self.good_bytes);
        
        // technically we should say "skipped" if we replaced a byte with itself, but this is fine for now
        Ok(MutationResult::Mutated)
    }
}

impl Named for AlphaByteSwapMutator {
    fn name(&self) -> &str {
        "AlphaByteSwapMutator"
    }
}

impl AlphaByteSwapMutator {
    fn new() -> Self {
        let mut good_bytes = Vec::new();

        for c in b'a'..=b'z' {
            good_bytes.push(c);
        }
        for c in b'A'..=b'Z' {
            good_bytes.push(c);
        }
        for c in b'0'..=b'9' {
            good_bytes.push(c);
        }
        good_bytes.push(b'-');
        good_bytes.push(b'_');

        Self {
            good_bytes
        }
    }
}

fn main() {

    println!("Starting up Emulator");

    env_logger::init();

    // first we have to start our modified QEMU instance
    // and run up to the point of our fuzzing
    // in our case, we want to run until "main" so libc is set up
    // then we will have each run just run the "tree" function

    env::remove_var("LD_LIBRARY_PATH");
    let env: Vec<(String, String)> = env::vars().collect();
    let args: Vec<String> = vec!["".into(), "../fuzz_target/target".into()];
    let emu = Emulator::new(&args, &env).unwrap();

    let mut elf_buf = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buf).unwrap();

    let mainptr = elf.resolve_symbol("main", emu.load_addr()).unwrap();

    println!("Main {mainptr:#x} , target func @ {parseptr:#x}");

    emu.set_breakpoint(mainptr);
    unsafe { emu.run() };

    // should have hit breakpoint at main
    let pc: GuestReg = emu.read_reg(Regs::Pc).unwrap();
    println!("Hit bp @ {pc:#x}");
    emu.remove_breakpoint(mainptr);

    // save the ret addr, so we can use it and stop after a run
    let retaddr: GuestAddr = emu.read_return_address().unwrap();
    emu.set_breakpoint(retaddr);

    let savedsp: GuestAddr = emu.read_reg(Regs::Sp).unwrap();

    // now let's map an area in the target we will use for our input
    let inputaddr = emu.map_private(0, 0x1000, MmapPerms::ReadWrite).unwrap();
    println!("Input page @ {inputaddr:#x}");

    // now we can make our fuzz harness that will reset the emulator each time
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();

        /*
            TODO

            Here we can setup the emulator for a single test case to run our input
            This will be run multiple times in a loop, so we have to reset any important state that may have changed each time

            Set the RIP, set the RSP, write the input into memory, set the input as an argument to the function, etc

            You can also experiment with adding the QemuSnapshotHelper so you can take and restore snapshots instead
            
            See:
            https://docs.rs/libafl_qemu/0.10.1/libafl_qemu/emu/struct.Emulator.html
        */

        // run until our breakpoint at the return address
        // or a crash
        emu.write_return_address(retaddr).unwrap();
        unsafe { emu.run() };

        // if we didn't crash, we are okay
        ExitKind::Ok
    };

    // we use a restarting manager which will restart
    // our process each time it crashes
    let mut shmem_provider = StdShMemProvider::new().unwrap();

    // we use a monitor to collect all the events
    let monitor = SimpleMonitor::new(|s| println!("{s}"));

    let (state, mut restarting_mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider) {
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                // done, stopping
                println!("Done");
                return;
            }
            _ => {
                panic!("Failed when setting up the restarting manager: {err}");
            }
        },

    };

    // observe
    // our modified qemu provides an edge map we can use
    let edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            edges_map_mut_slice(),
            addr_of_mut!(MAX_EDGES_NUM),
        ))
    };


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

    // create our hooks which help
    // we could add a lot of cool helpers
    // QemuSnapshotHelper, QemuAsanHelper, QemuCmpLogHelper, etc

    let mut hooks = QemuHooks::new(
        &emu,
        tuple_list!(
            QemuEdgeCoverageHelper::default(),
        ),
    );

    // and our Qemu Executor
    let mut executor = QemuExecutor::new(
        &mut hooks,
        &mut harness,
        tuple_list!(edges_observer),
        &mut fuzzer,
        &mut state,
        &mut restarting_mgr,
    ).unwrap();

    // we need to check if our in memory corpus is empty first
    if state.must_load_initial_inputs() {
        state.load_initial_inputs(&mut fuzzer, &mut executor, &mut restarting_mgr, &[PathBuf::from("../fuzz_target/uid_corpus/")]).unwrap();
        println!("Loaded initial inputs");
    }

    // set up mutation
    let mutator = StdScheduledMutator::with_max_stack_pow(
        tuple_list!(
            AlphaByteSwapMutator::new(),
            BytesDeleteMutator::new(),
            BytesInsertMutator::new(),
        ),
        9,
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // run it
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr).unwrap();
}
