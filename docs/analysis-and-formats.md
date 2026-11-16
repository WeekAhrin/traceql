# Analysis and output formats

TraceQL combines source-level Clang AST inspection, post-optimization LLVM IR analysis, cross-translation-unit call graph aggregation, and external threat-intel matching to provide deep behavioral profiling for EDR and anti-cheat developers.

## Detection stages

TraceQL provides granular analysis of code structure, entropy, and execution patterns to help profile and model EDR and anti-cheat behavior.

### 1. Clang AST inspection (`TraceQL.so`)

The AST consumer inspects call expressions, function pointers, string/byte literals, inline assembly, auto-init attributes, mutex operations, and intra-procedural data flows:

- **Runtime symbol resolution** — detects `dlopen`/`dlsym`, `LoadLibrary`/`GetProcAddress`, and indirect calls, optionally matching resolved library symbols via `BinarySymbolParser`.
- **Intra-procedural taint tracking** — propagates bitmask taint kinds (`MemoryAlloc`, `DynamicResolve`, `HighEntropyBlob`, `StackString`, `ExecProtect`) within functions to profile chained behavior.
- **Behavior classification** — classifies calls and literals into categories (`MemoryAllocation`, `MemoryProtection`, `DynamicResolution`, `DirectSyscall`, `IndirectCall`, `ProcessThreadOp`, `ObfuscatedPayload`, `AntiDebugOrTiming`, `NetworkOrIPC`, `FileOrRegistryIO`).
- **Obfuscation and crypto indicators** — computes Shannon entropy to profile packed payloads, detects XOR decoding loops, identifies auto-init entrypoints, tracks stack-constructed strings, and recognizes common constants (`fnv1a_hash`, `crc32_poly`, `chacha20_const`, `aes_sbox`, `ror13_hash`, `djb2_hash`).

### 2. LLVM IR inspection (`TraceQLIR.so`)

Running `TraceQLIR.so` at `-O2` inspects code after constant propagation, dead-code elimination, and target lowering:

- Recovers constant-folded stack strings and printable global payloads.
- Resolves indirect callees across casts, `select`, `phi`, aliases, and constant global tables.
- Classifies inline assembly instructions and inspects global initializers above entropy thresholds.

### 3. Cross-TU aggregation and concurrency checks (`traceql_merge`)

`traceql_merge` combines per-TU pattern files and function summaries across the project to calculate overall risk and behavioral profiles:

- Deduplicates call records and computes cross-TU reachability.
- Detects AB/BA lock-order inversions across translation units with `LockAnalyzer`.
- Matches observed symbols, entropy signatures, and behavior indicators against threat-intel datasets (`malapi`, `lolbas`, `sigma`, `elastic`) to benchmark project behavior against known patterns.

## Bundled datasets

Datasets live under `datasets/` and are loaded by `--load-dataset=datasets` (the default in [`traceql`](../traceql)):

| Directory | Format | Content |
| :--- | :--- | :--- |
| `datasets/malapi/` | JSON | Malicious API behavior mappings (`malapi.json`) |
| `datasets/lolbas/` | JSON | Living Off The Land Binaries and Scripts (`lolbas.json`) |
| `datasets/sigma/` | YAML | SigmaHQ Linux and Windows detection rules |
| `datasets/elastic/` | TOML | Elastic protections-artifacts detection rules |

To refresh all four sources from upstream repositories, run [`datasets/update_datasets.sh`](../datasets/update_datasets.sh).

## Output formats

| Output | Flag | Format details |
| :--- | :--- | :--- |
| Behavior findings (JSON) | `--behavior-format=json` | Structured JSON array of findings with risk score, category, tags, source location, and caller |
| Sigma YAML rules | `--behavior-format=sigma` | Portable Sigma detection rules derived from observed call and command indicators |
| SARIF v2.1.0 | `--behavior-format=sarif` | Static Analysis Results Interchange Format for CI code-scanning integration |
| Cross-TU patterns | `--emit-patterns=PATH` | Merged per-call records and function summaries JSON |
| Call graphs | `--emit-mermaid=PATH`, `--emit-dot=PATH` | Mermaid flowchart (`.mmd`) and Graphviz DOT (`.dot`) visualizations |
