# Building TraceQL

TraceQL builds on Linux, macOS, and Windows with CMake 3.20 or newer and a C++20 compiler.

## Prerequisites

- CMake 3.20 or newer
- C++20 compiler (`clang++` or `g++`)
- Clang and LLVM development headers on include paths if compiling the plugin targets
- Python 3.10 or newer for the [`traceql`](../traceql) incremental runner
- `GTest` (found automatically via `find_package(GTest REQUIRED)` or a vendored tree)

## Configure and build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## Run tests

```bash
ctest --test-dir build --output-on-failure
```

You can run the GoogleTest binary directly to filter suites:

```bash
./build/test_traceql --gtest_brief=1
```

## Build targets

| Target | Artifact | Role |
| :--- | :--- | :--- |
| `TraceQL` | `build/TraceQL.so` | Clang AST plugin (`-add-plugin traceql`) |
| `TraceQLIR` | `build/TraceQLIR.so` | LLVM pass plugin (`traceql-ir`) |
| `traceql_merge` | `build/traceql_merge` | Cross-TU pattern aggregator and report emitter |
| `test_traceql` | `build/test_traceql` | Unit test binary (`TraceQLTests` in CTest) |
| `TraceQLPlatform` | `build/libTraceQLPlatform.a` | Platform and header classifier |
| `TraceQLSymbols` | `build/libTraceQLSymbols.a` | Binary symbol and remote resolver |
| `TraceQLAnalysis` | `build/libTraceQLAnalysis.a` | Behavior, dataset, entropy, lock, points-to, and taint analyzers |
| `TraceQLPatterns` | `build/libTraceQLPatterns.a` | Call pattern collector and behavior rule emitters |
| `TraceQLAggregator` | `build/libTraceQLAggregator.a` | Cross-TU graph builder, Mermaid, DOT, and SARIF exporter |
| `TraceQLIRCore` | `build/libTraceQLIRCore.a` | Inline assembly classifier and IR string recovery |

## Bundled dependencies

Third-party libraries live under `third_party/`:

| Dependency | Version | Integration |
| :--- | :--- | :--- |
| `yaml-cpp` | `0.8.0` | Static library built from `third_party/yaml-cpp` |
| `nlohmann/json` | `3.11.2` | Header-only target from `third_party/nlohmann/json.hpp` |
