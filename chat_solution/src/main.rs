
use std::{
    env,
    path::PathBuf,
    ptr::addr_of_mut,
};

use libafl_bolts::{
    tuples::{
        tuple_list,
    },
    shmem::{ShMemProvider, StdShMemProvider},
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
    monitors::SimpleMonitor,
    mutators::{
        scheduled::{
            StdScheduledMutator,
        },
        havoc_mutations,
    },
    stages::mutational::StdMutationalStage,
    observers::map::{
        HitcountsMapObserver,
        VariableMapObserver,
    },
    state::{
        StdState,
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
    snapshot::QemuSnapshotHelper,
};

fn main() {

    println!("Starting up Emulator");

    env_logger::init();

    env::remove_var("LD_LIBRARY_PATH");
    let env: Vec<(String, String)> = env::vars().collect();
    let args: Vec<String> = vec!["".into(), "../chat_target/chat".into()];
    let emu = Emulator::new(&args, &env).unwrap();

    let mut elf_buf = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buf).unwrap();

    let mainptr = elf.resolve_symbol("main", emu.load_addr()).unwrap();
    let handlemsg = elf.resolve_symbol("handle_msg", emu.load_addr()).unwrap();

    println!("Main {mainptr:#x} , target func @ {handlemsg:#x}");

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
    let inputmax = 0x1000;
    let inputaddr = emu.map_private(0, inputmax, MmapPerms::ReadWrite).unwrap();
    println!("Input page @ {inputaddr:#x}");

    // we could use QEMU system mode to do snapshots
    // but the snapshot helper will do it for us
    // so each time we will run the same snapshot, removing global state issues

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();

        // limit out input size
        if len > inputmax {
            buf = &buf[0..inputmax];
            len = inputmax;
        }

        if len < 8 {
            return ExitKind::Ok;
        }

        //TODO some crashes are way easier to hit than others
        // we could either fix/patch the target to get past those
        // or we could reject cases we know hit those areas
        // (like the /nick cmd)
        let msgtype = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        if msgtype == 3 || msgtype == 4 {
            // avoid nick cmd and art cmd
            // we crash there too much
            return ExitKind::Ok;
        }

        // write our testcase into memory
        unsafe {
            emu.write_mem(inputaddr, buf);
            // adjust the datalength field to match, as it will when recv'd
            emu.write_mem(inputaddr + 6, &(len as u16).to_le_bytes())

        };
        // reset the registers as needed
        emu.write_reg(Regs::Pc, handlemsg).unwrap();
        emu.write_reg(Regs::Sp, savedsp).unwrap();
        emu.write_return_address(retaddr).unwrap();

        // a file descriptor for the connection
        // some messages send stuff back, we are using an invalid fd here and it should be fine
        emu.write_reg(Regs::Rdi, 42u64).unwrap();

        // our msg buffer
        emu.write_reg(Regs::Rsi, inputaddr).unwrap();

        // run until our breakpoint at the return address
        // or a crash
        unsafe { emu.run() };

        // if we didn't crash, we are okay

        ExitKind::Ok
    };

    let mut shmem_provider = StdShMemProvider::new().unwrap();

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

    //TODO add ASAN helper
    let mut hooks = QemuHooks::new(
        &emu,
        tuple_list!(
            QemuEdgeCoverageHelper::default(),
            QemuSnapshotHelper::new(),
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

    if state.must_load_initial_inputs() {
        state.load_initial_inputs(&mut fuzzer, &mut executor, &mut restarting_mgr, &[PathBuf::from("./corpus/")]).unwrap();
        println!("Loaded initial inputs");
    }

    let mutator = StdScheduledMutator::with_max_stack_pow(
        havoc_mutations(),
        9,
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // run it
    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr).unwrap();
}
