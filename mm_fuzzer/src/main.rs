extern crate libafl;
extern crate libafl_bolts;

use std::path::PathBuf;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::forkserver::ForkserverExecutor,
    feedbacks::{Feedback, CrashFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{scheduled::HavocScheduledMutator, havoc_mutations},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
    events::EventFirer,
    observers::ObserversTuple,
    Error,
};
use libafl_bolts::{
    rands::StdRand,
    tuples::tuple_list,
    shmem::{ShMemProvider, UnixShMemProvider},
    Named,
};
use std::path::Path;

// ── leer veredicto del MM desde archivo ──────────────────────────────────────
fn read_mm_verdict() -> u8 {
    std::fs::read_to_string("/tmp/mm_verdict")
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .unwrap_or(0)
}

// ── Feedback custom: interesante si MM emitió IV ─────────────────────────────
struct IVFeedback;

impl Named for IVFeedback {
    fn name(&self) -> &str {
        "IVFeedback"
    }
}

impl<S> Feedback<S> for IVFeedback
where
    S: libafl::state::State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &libafl::executors::ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(read_mm_verdict() == 2)  // 2 = IV
    }

    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

// ── main ─────────────────────────────────────────────────────────────────────
fn main() {

    // path al PUA instrumentado con MM
    let pua_path = "/path/to/coreutils/src/instrumentedPUA";

    // EVENT MANAGER
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(mon);

    // FEEDBACK
    let mut feedback = IVFeedback;
    let mut objective = CrashFeedback::new();

    // STATE
    let mut state = StdState::new(
        StdRand::new(),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    // FUZZER
    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // EXECUTOR — corre el PUA como proceso separado
    let mut executor = ForkserverExecutor::builder()
        .program(pua_path)
        .parse_afl_cmdline(["@@"])  // @@ = archivo con el input
        .build(tuple_list!())
        .unwrap();

    // SEEDS — cargás inputs reales en lugar de strings aleatorios
    state.load_initial_inputs(
        &mut fuzzer,
        &mut executor,
        &mut mgr,
        &[PathBuf::from("./seeds")],
    )
    .expect("Failed to load seeds");

    // LOOP
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

// **Lo que necesitás para correrlo:**

// 1. Carpeta `seeds/` con inputs reales, uno por archivo:

// seeds/
//   seed1    ← "archivo.txt"
//   seed2    ← "-n archivo.txt"