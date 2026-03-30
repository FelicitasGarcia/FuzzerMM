extern crate libafl;
extern crate libafl_bolts; 

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{scheduled::{HavocScheduledMutator}, havoc_mutations},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list, AsSlice, nonzero};
use std::path::PathBuf;


// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];

fn signals_set(idx: usize) {
    unsafe { SIGNALS[idx] = 1 };
}



fn main() {
    // HARNESS
    let mut harness = |input: &BytesInput| {
        // unsafe { main_del_PUA(...) };
        // BEGINNING OF FUNCTION UNDER TEST
        let target = input.target_bytes();
        let buf = target.as_slice();
        signals_set(0); // set SIGNALS[0]
        if buf.len() > 0 && buf[0] == 'a' as u8 {
            signals_set(1); // set SIGNALS[1]
            if buf.len() > 1 && buf[1] == 'b' as u8 {
                signals_set(2); // set SIGNALS[2]
                if buf.len() > 2 && buf[2] == 'c' as u8 {
                    panic!("=)");
                }
            }
        }
        // END OF FUNCTION UNDER TEST
        ExitKind::Ok // What the executor expectrs the harness to return
    };

    // EVENT MANAGER
    let mon = SimpleMonitor::new(|s| println!("{s}")); // Monitor defines how fuzzer stats are displayed
    let mut mgr = SimpleEventManager::new(mon); // Event manager handles the various events generated during the fuzzing loop

    // GENERATOR
    let mut generator = RandPrintablesGenerator::new(nonzero!(32));

    // OBSERVATOR
    // Create an observation channel using the signals map
    let observer = unsafe { StdMapObserver::new("signals", &mut SIGNALS[..]) };

    // FEEDBACK
    let mut feedback = MaxMapFeedback::new(&observer); // rate the interestingness of an input

    // FEEDBACK: to determine whether an input is a solution or not
    let mut objective = CrashFeedback::new(); 

    // STATE
    let mut state = StdState::new(
        // Random Number Generator
        StdRand::new(),
        // Evolving Corpus (In Memory)
        InMemoryCorpus::new(),
        // Solutions Corpus (On Disk)
        OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    // FUZZER
    let scheduler = QueueScheduler::new();  // Corpus Scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);   

    // EXECUTOR
     let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

}

