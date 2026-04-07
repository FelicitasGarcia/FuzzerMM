# FuzzerMM

A fuzzing framework built on [LibAFL](https://github.com/AFLplusplus/LibAFL) that integrates with **MimicryMonitor (MM)** — a dynamic analysis tool that monitors program behavior and emits verdicts about whether a program is exhibiting divergent behavior (Impossible to Verify, IV).

This project contains the following fuzzer: 
- **`mm_fuzzer`** — drives a Program Under Analysis (PUA) instrumented with MimicryMonitor, collecting inputs that trigger IV verdicts.

---

## How It Works

1. Loads seed inputs from `./seeds/`.
2. Runs the instrumented PUA as a **separate process** for each generated input, passing the input as a command-line argument.
3. After each execution, reads `/tmp/mm_verdict` — a file written by MimicryMonitor — to check the verdict:
   - `2` → MimicryMonitor flagged the execution as an IV (interesting behavior). The input is saved to `./iv_inputs/`.
   - Any other value → input is discarded.
4. Mutates interesting inputs (Havoc strategy) and repeats.

The goal is to automatically find inputs that cause the PUA to trigger edivergent behaviour.

---

## Project Structure

```
FuzzerMM/
├── mm_fuzzer/           # Main fuzzer integrating with MimicryMonitor
│   ├── src/main.rs
│   ├── seeds/           # Initial inputs fed to the fuzzer
│   ├── iv_inputs/       # Inputs that triggered an IV verdict (saved automatically)
│   ├── crashes/         # Crash corpus (currently unused)
│   └── Cargo.toml
└── LibAFL/              # Local LibAFL source (submodule)
```

---

## Requirements

- Rust (stable toolchain, edition 2021+)
- A compiled, MM-instrumented PUA binary at the path set in `mm_fuzzer/src/main.rs`:
  ```
  /Users/felicitasgarcia/MM/mimicrymonitor/llvm/feli/outputs/instrumentedPUA
  ```
- MimicryMonitor must be set up to write its verdict to `/tmp/mm_verdict` after each PUA execution.

---

## Building

```bash
# Build the main MM fuzzer
cd ../mm_fuzzer
cargo build --release
```

---

## Running

Make sure the instrumented PUA binary exists and MimicryMonitor is configured to write to `/tmp/mm_verdict`, then:

```bash
cd mm_fuzzer
cargo run --release
```

The fuzzer will:
- Load seeds from `./seeds/`
- Run indefinitely, mutating inputs
- Save any input that produced a verdict of `2` into `./iv_inputs/`

To stop it, press `Ctrl+C`.

---

## Seeds

The `mm_fuzzer/seeds/` directory contains the initial corpus. Each file is a raw byte input passed directly to the PUA:

| File        | Description              |
| ----------- | ------------------------ |
| `seed_0`    | Input representing `0`   |
| `seed_1`    | Input representing `1`   |
| `seed_neg1` | Input representing `-1`  |
| `seed_min`  | Minimum boundary value   |
| `seed_max`  | Maximum boundary value   |
| `seed_255`  | Input representing `255` |
| `seed_256`  | Input representing `256` |

---

```
        ⢰⣿⠛⠷⡞⠛⢳⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠘⣷⠑⡆⢳⡆⠀⣿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⢅⡹⡈⠿⡀⢹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⠐⡜⠣⠬⠙⠦⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣠⣤⠛⠛⠛⠛⣤⣍⡏⠁⠀⠀⣀⣀⠈⢻⡄⠀⠀⠀⠀
⠀⣠⡔⠉⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠀⠙⠛⠀⢨⣿⠀⠀⠀⠀
⢠⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⡟⠀⠀⠀⠀⠀
⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠉⠀⠀⠀⠀⠀⠀⠀
⠸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠻⢆⣴⣤⣤⣤⣯⣭⣵⣦⣤⣤⣼⣄⡸⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⡀
```
