# Usage and CLI

TraceQL can scan an entire project from `compile_commands.json`, run inside individual Clang compilation commands, or merge pre-generated per-TU pattern JSON files.

## Incremental project scan

Use [`traceql`](../traceql) against any C or C++ project that generates `compile_commands.json`:

```bash
./traceql \
  --compile-commands /path/to/build/compile_commands.json \
  --emit-patterns build/patterns.json \
  --emit-behavior-rules build/findings.sarif \
  --behavior-format sarif
```

Add `--with-ir` to run [`TraceQLIR.so`](../ir/ir_pass.cpp) at `-O2` alongside the AST pass:

```bash
./traceql \
  --compile-commands /path/to/build/compile_commands.json \
  --with-ir \
  --emit-behavior-rules build/findings.json \
  --emit-mermaid build/graph.mmd \
  --emit-dot build/graph.dot
```

### Incremental runner options

| Option | Default | Description |
| :--- | :--- | :--- |
| `--compile-commands PATH` | Required | Path to `compile_commands.json` |
| `--build-dir DIR` | `build` | Directory holding `TraceQL.so`, `TraceQLIR.so`, and `traceql_merge` |
| `--cache-dir DIR` | `.traceql_cache` | Directory for dependency tracking and cached per-TU JSON files |
| `--no-cache` | Off | Ignore cached per-TU outputs and re-analyze every translation unit |
| `--with-ir` | Off | Also compile each TU with `-O2` through `TraceQLIR.so` |
| `--filter REGEX` | Empty | Include only TU file paths matching `REGEX` |
| `--exclude REGEX` | Empty | Exclude TU file paths matching `REGEX` |
| `--dataset PATH` | `datasets` | Threat-intel dataset file or directory |
| `--emit-patterns PATH` | Empty | Write merged cross-TU patterns JSON |
| `--emit-behavior-rules PATH` | Empty | Write behavior findings (`.json`, `.yml`, or `.sarif`) |
| `--behavior-format FMT` | Auto | Output format override: `json`, `sigma`, or `sarif` |
| `--emit-mermaid PATH` | Empty | Write Mermaid flowchart (`.mmd`) |
| `--emit-dot PATH` | Empty | Write Graphviz DOT graph (`.dot`) |
| `--diff-base REF` | Empty | Git ref for PR mode; keeps findings touching changed files or lines |
| `--target-os OS` | `auto` | Target platform classification: `auto`, `windows`, `linux`, or `android` |
| `--risk-threshold N` | `40` | Minimum risk score (`0`–`100`) to report |
| `--entropy-threshold F` | `6.8` | Shannon entropy threshold for packed or encrypted payload detection |
| `--jobs N` | CPU count | Parallel worker count |

## Direct Clang plugin invocation

Run the AST plugin directly on a single translation unit:

```bash
clang++ -fsyntax-only \
  -fplugin=./build/TraceQL.so \
  -Xclang -add-plugin -Xclang traceql \
  -Xclang -plugin-arg-traceql -Xclang --emit-patterns=tu.ast.json \
  -Xclang -plugin-arg-traceql -Xclang --load-dataset=./datasets \
  -Xclang -plugin-arg-traceql -Xclang --emit-behavior-rules=tu.findings.json \
  path/to/file.cpp
```

### AST plugin arguments

Pass each argument with `-Xclang -plugin-arg-traceql -Xclang <arg>`:

- `--emit-patterns=<file>` — write per-TU call and function summary JSON
- `--emit-behavior-rules=<file>` — write single-TU behavior findings
- `--behavior-format=<json|sigma|sarif>` — select findings format
- `--load-dataset=<path>` / `--load-rules=<path>` — load rule datasets from a file or directory
- `--scan-lib=<path>` / `--scan-dir=<path>` — index symbols from extra shared libraries or directories
- `--no-auto-scan` — skip scanning default system library directories
- `--target-os=<auto|windows|linux|android>` — override target platform detection
- `--risk-threshold=<N>` — set risk score threshold (default `40`)
- `--entropy-threshold=<F>` — set Shannon entropy threshold (default `6.8`)
- `--strict-behavior-warn` — emit Clang compiler diagnostics for flagged behavior

## Direct LLVM IR pass invocation

Run the optimization-time pass (`traceql-ir`) at `-O2`:

```bash
clang++ -O2 -g -c -o /dev/null \
  -fpass-plugin=./build/TraceQLIR.so \
  -mllvm -traceql-ir-out=tu.ir.json \
  -mllvm -traceql-ir-warn \
  path/to/file.cpp
```

## Merging translation units

Merge multiple AST and IR JSON files with `traceql_merge`:

```bash
./build/traceql_merge \
  --load-dataset=./datasets \
  --emit-patterns=merged.json \
  --emit-behavior-rules=findings.sarif \
  --behavior-format=sarif \
  --emit-mermaid=callgraph.mmd \
  --emit-dot=callgraph.dot \
  tu1.ast.json tu1.ir.json tu2.ast.json
```
