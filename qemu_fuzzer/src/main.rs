
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

    // all the qemu fuzzers do this, why?
    // To make sure we use the right one?
    env::remove_var("LD_LIBRARY_PATH");
    let env: Vec<(String, String)> = env::vars().collect();
    let args: Vec<String> = vec!["".into(), "../fuzz_target/target".into()];
    let emu = Emulator::new(&args, &env).unwrap();

    let mut elf_buf = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buf).unwrap();

    let mainptr = elf.resolve_symbol("main", emu.load_addr()).unwrap();
    let parseptr = elf.resolve_symbol("uid_to_name", emu.load_addr()).unwrap();

    println!("Main {mainptr:#x} , target func @ {parseptr:#x}");

    emu.set_breakpoint(mainptr);
    unsafe { emu.run() };

    // should have hit breakpoint at main
    let pc: GuestReg = emu.read_reg(Regs::Pc).unwrap();
    println!("Hit bp @ {pc:#x}");
    emu.remove_breakpoint(mainptr);

    // save the ret addr, so we can use it and stop
    let retaddr: GuestAddr = emu.read_return_address().unwrap();
    emu.set_breakpoint(retaddr);

    let savedsp: GuestAddr = emu.read_reg(Regs::Sp).unwrap();

    // now let's map an area in the target we will use for the input.
    let inputaddr = emu.map_private(0, 0x1000, MmapPerms::ReadWrite).unwrap();
    println!("Input page @ {inputaddr:#x}");

    // now we can make our fuzz harness that will reset the emulator each time
    // if there was a lot of extra state, we might want to use a qemu snapshot instead

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();

        // limit out input size
        if len > 1024 {
            buf = &buf[0..1024];
            len = 1024;
        }

        // here we could fuzz main like normal
        // or we could fuzz the process_line function
        // but we would have to free the result each time
        // so let's isolate the uid_to_name function and just fuzz that
        // because it just takes in a null terminated string and does not affect global state
        // so it is very fuzzable
        // however, it is after the invalid character validation
        // so we need to limit our mutations to only use valid characters
        // we will use the same custom mutator as before

        // write our testcase into memory, null terminated
        unsafe {
            emu.write_mem(inputaddr, buf);
            emu.write_mem(inputaddr + (len as u64), b"\0\0\0\0");
        };
        // reset the registers as needed
        emu.write_reg(Regs::Pc, parseptr).unwrap();
        emu.write_reg(Regs::Sp, savedsp).unwrap();
        emu.write_return_address(retaddr).unwrap();
        emu.write_reg(Regs::Rdi, inputaddr).unwrap();

        // run until our breakpoint at the return address
        // or a crash
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
