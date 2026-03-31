extern crate libafl;
extern crate libafl_bolts;

use std::path::PathBuf;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{Feedback, CrashFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{scheduled::HavocScheduledMutator, havoc_mutations},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{State, StdState},
    events::EventFirer,
    observers::ObserversTuple,
    Error,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list, AsSlice, nonzero};

// ── TODO: PUA instrumentado con MM que guarde variable global con el veredicto ────────────────────────────────────────────
extern "C" {
    fn run_pua(data: *const u8, size: usize);
    static mut MM_VERDICT: u8;  // escrito por monitorAction en el PUA
}

// ── Feedback custom: interesante si MM emitió IV ─────────────────────────── 
struct IVFeedback;

impl<S> Feedback<S> for IVFeedback
where
    S: State,               
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let verdict = unsafe { MM_VERDICT };
        Ok(verdict == 2)  // 2 = IV
    }                                   

    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for IVFeedback {
    fn name(&self) -> &str {
        "IVFeedback"
    }
}

// ── main ────────────────────────────────────────────────────────────────────
fn main() {

    // HARNESS
    let mut harness = |input: &BytesInput| {
        let buf = input.target_bytes();
        let slice = buf.as_slice();

        // resetear veredicto antes de cada ejecución
        unsafe { MM_VERDICT = 0; }

        // correr el PUA instrumentado con MM
        unsafe { run_pua(slice.as_ptr(), slice.len()); }

        ExitKind::Ok
    };

    // EVENT MANAGER
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(mon);

    // FEEDBACK
    let mut feedback = IVFeedback;         // interesante = IV
    let mut objective = CrashFeedback::new(); // solución = crash

    // STATE
    let mut state = StdState::new(
        StdRand::new(),
        InMemoryCorpus::new(),             // corpus en memoria
        OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap(), // IVs guardados en disco
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    // FUZZER
    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // EXECUTOR
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(),                     // sin observer de cobertura, el feedback es el MM
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // INPUTS INICIALES
    let mut generator = RandPrintablesGenerator::new(nonzero!(32));
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // LOOP
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}