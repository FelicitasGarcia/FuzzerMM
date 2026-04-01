extern crate libafl;
extern crate libafl_bolts;

use std::borrow::Cow;
use std::path::PathBuf;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::{EventFirer, SimpleEventManager},
    executors::command::CommandExecutor,
    feedbacks::{Feedback, CrashFeedback, StateInitializer},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
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
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &libafl::executors::ExitKind,
    ) -> Result<bool, Error> {
        Ok(read_mm_verdict() == 2)  // 2 = IV
    }
}

// ── main ─────────────────────────────────────────────────────────────────────
fn main() {

    // path al PUA instrumentado con MM
    let pua_path = "/Users/felicitasgarcia/MM/mimicrymonitor/llvm/feli/outputs/instrumentedPUA";

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

    // EXECUTOR — corre el PUA como proceso separado (un proceso por input)
    let mut executor = CommandExecutor::builder()
        .program(pua_path)
        .arg_input_file_std()   // escribe el input a un archivo temporal y lo pasa como argumento
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
