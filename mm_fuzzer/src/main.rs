extern crate libafl;
extern crate libafl_bolts;

use std::borrow::Cow;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use libafl::{
    corpus::OnDiskCorpus,
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

// ── Feedback custom: interesante si MM emitió IV, sin duplicados ─────────────
struct IVFeedback {
    seen: HashSet<Vec<u8>>,
    last_iv_found: Arc<Mutex<Instant>>,
}

impl IVFeedback {
    fn new(last_iv_found: Arc<Mutex<Instant>>) -> Self {
        Self { seen: HashSet::new(), last_iv_found }
    }
}

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
        _input: &I,
        _observers: &OT,
        _exit_kind: &libafl::executors::ExitKind,
    ) -> Result<bool, Error> {
        let bytes = _input.target_bytes();
        let raw = std::fs::read_to_string("/tmp/mm_verdict");
        let verdict = raw
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .unwrap_or(0);

        println!("[exec] input: {:?}  verdict: {}", String::from_utf8_lossy(&bytes), verdict);

        if verdict != 2 {
            return Ok(false);
        }

        let key = bytes.to_vec();
        if self.seen.contains(&key) {
            println!("[IVFeedback] IV duplicado, descartado: {}", String::from_utf8_lossy(&key));
            return Ok(false);
        }

        self.seen.insert(key.clone());
        *self.last_iv_found.lock().unwrap() = Instant::now();
        println!("[IVFeedback] IV nuevo encontrado: {}", String::from_utf8_lossy(&key));
        Ok(true)
    }
}

// ── main ─────────────────────────────────────────────────────────────────────
fn main() {
    let pua_path = "/Users/felicitasgarcia/MM/mimicrymonitor/llvm/feli/outputs/instrumentedPUA";

    let mon = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(mon);

    let last_iv_found = Arc::new(Mutex::new(Instant::now()));

    let mut feedback = IVFeedback::new(Arc::clone(&last_iv_found));
    let mut objective = libafl::feedbacks::ConstFeedback::new(false);

    let mut state = StdState::new(
        StdRand::new(),
        OnDiskCorpus::<BytesInput>::new(PathBuf::from("./iv_inputs")).unwrap(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
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
        &[PathBuf::from("./seeds")],
    )
    .expect("Failed to load seeds");

    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    loop {
        if last_iv_found.lock().unwrap().elapsed() > IDLE_TIMEOUT {
            println!("[timeout] No se encontraron IVs nuevos en {}s, terminando.", IDLE_TIMEOUT.as_secs());
            break;
        }

        match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            Ok(_) => {},
            Err(e) => eprintln!("[WARN] fuzz_one error (skipped): {e:?}"),
        }
    }
}
