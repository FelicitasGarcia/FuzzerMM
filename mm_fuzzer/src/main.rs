extern crate libafl;
extern crate libafl_bolts;
extern crate num_bigint;

use std::borrow::Cow;
use std::path::PathBuf;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::{EventFirer, SimpleEventManager},
    executors::{command::CommandExecutor, StdChildArgs},
    feedbacks::{Feedback, StateInitializer},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{scheduled::HavocScheduledMutator, havoc_mutations},
    observers::ObserversTuple,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
    Error,
};
use libafl_bolts::{
    rands::StdRand,
    tuples::tuple_list,
    Named, StdTargetArgs,
};

// ── Feedback: interesante si MM emitió IV ────────────────────────────────────
struct IVFeedback;

impl Named for IVFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("IVFeedback");
        &NAME
    }
}

impl<S> StateInitializer<S> for IVFeedback {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for IVFeedback
where
    S: libafl::state::State,
    EM: EventFirer<I, S>,
    OT: ObserversTuple<I, S>,
    I: HasTargetBytes,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &I,
        _observers: &OT,
        exit_kind: &libafl::executors::ExitKind,
    ) -> Result<bool, Error> {
        let bytes = input.target_bytes();
        println!("[IVFeedback] input: {:?}", String::from_utf8_lossy(&bytes));
        let crashed = matches!(exit_kind, libafl::executors::ExitKind::Crash);
        if crashed {
            println!("[IVFeedback] crash detectado → interesting: true");
            return Ok(true);
        }
        let raw = std::fs::read_to_string("/tmp/mm_verdict");
        println!("[IVFeedback] /tmp/mm_verdict raw: {:?}", raw);
        let verdict = raw
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .unwrap_or(0);
        println!("[IVFeedback] parsed verdict: {} → interesting: {}", verdict, verdict == 2);
        let interesting = verdict == 2;
        if interesting {
            println!("[IVFeedback] IV detectado — input (string): {:?}", String::from_utf8_lossy(&bytes));
        }
        Ok(interesting)
    }
}

// ── main ─────────────────────────────────────────────────────────────────────
fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let seeds_dir = manifest_dir.join("seeds");
    let crashes_dir = manifest_dir.join("crashes");

    let pua_path = std::env::var("MM_PUA_PATH").unwrap_or_else(|_| {
        "/home/felicitas/DOC/MM/MimicryMonitor/llvm/feli/outputs/instrumentedPUA".to_string()
    });

    if !seeds_dir.is_dir() {
        panic!("Seeds directory not found at {}", seeds_dir.display());
    }

    let mon = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(mon);

    let mut feedback = IVFeedback;
    let mut objective = libafl::feedbacks::ConstFeedback::new(false);

    let mut state = StdState::new(
        StdRand::new(),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(crashes_dir).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = CommandExecutor::builder()
        .program(pua_path)
        .arg_input_arg()
        .timeout(std::time::Duration::from_secs(5))
        .build(tuple_list!())
        .unwrap();

    state.load_initial_inputs(
        &mut fuzzer,
        &mut executor,
        &mut mgr,
        &[seeds_dir],
    )
    .expect("Failed to load seeds");

    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    loop {
        // Limpiar el archivo ANTES de correr el PUA para evitar valores stale
        let _ = std::fs::write("/tmp/mm_verdict", "0");
        match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            Ok(_) => {}
            Err(libafl::Error::OsError(..)) => {}
            Err(e) => panic!("Error fatal en el loop: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
