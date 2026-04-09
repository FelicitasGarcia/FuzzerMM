extern crate libafl;
extern crate libafl_bolts;

use std::borrow::Cow;
use std::path::PathBuf;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::{EventFirer, SimpleEventManager},
    executors::command::CommandExecutor,
    feedbacks::{Feedback, StateInitializer},
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
    I: libafl::inputs::HasTargetBytes,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &libafl::executors::ExitKind,
    ) -> Result<bool, Error> {
        let bytes = _input.target_bytes();
        println!("[IVFeedback] input (hex): {}", bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "));
        let raw = std::fs::read_to_string("/tmp/mm_verdict");
        println!("[IVFeedback] /tmp/mm_verdict raw: {:?}", raw);
        let verdict = raw
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .unwrap_or(0);
        println!("[IVFeedback] parsed verdict: {} → interesting: {}", verdict, verdict == 2);
        Ok(verdict == 2)
    }
}

// ── main ─────────────────────────────────────────────────────────────────────
fn main() {

    // path al PUA instrumentado con MM
    let pua_path = "/Users/felicitasgarcia/MM/mimicrymonitor/llvm/feli/outputs/instrumentedPUA";

    // EVENT MANAGER
    let mon = SimpleMonitor::new(|s| {
        let s = s
            .replace("pizzas", "corpus")
            .replace("deliveries", "objectives")
            .replace("doughs", "executions")
            .replace("customers", "clients")
            .replace("time to bake", "run time")
            .replace("p/s", "exec/s");
        println!("{s}");
    });
    let mut mgr = SimpleEventManager::new(mon);

    // FEEDBACK
    let mut feedback = IVFeedback;
    let mut objective = libafl::feedbacks::ConstFeedback::new(false); // nunca crashea

    // STATE 
    let mut state = StdState::new(
        StdRand::new(),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
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
        .arg_input_arg()   // pasa el input directamente como argumento en la línea de comandos
        .build(tuple_list!())
        .unwrap();

    // SEEDS — carga solo el seed -1
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

    loop {
        match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            Ok(_) => {},
            Err(libafl::Error::OsError(..)) => {}, // input con null byte, se saltea
            Err(e) => panic!("Error fatal en el loop: {e}"),
        }
    }
}

