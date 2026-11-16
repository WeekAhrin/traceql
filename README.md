<div align="center">

# TraceQL

![C++20](https://img.shields.io/badge/C%2B%2B-20-blue)
![Clang AST](https://img.shields.io/badge/Clang-AST%20Plugin-blueviolet)
![LLVM IR](https://img.shields.io/badge/LLVM-IR%20Pass-informational)
![CMake 3.20+](https://img.shields.io/badge/CMake-3.20%2B-064F8C)

![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)
![macOS](https://img.shields.io/badge/macOS-000000?logo=apple&logoColor=white)
![Android](https://img.shields.io/badge/Android-3DDC84?logo=android&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D4?logo=windows&logoColor=white)

</div>

TraceQL — это C++20 Clang AST плагин, `-O2` LLVM IR проход и анализатор кросс-трансляционных единиц для C и C++ кодовых баз. Основная функция инструмента — глубокий поведенческий анализ исходного кода для разработки и профилирования EDR-систем и античитов.

TraceQL вычисляет энтропию данных и паттерны выполнения, позволяя моделировать и верифицировать поведение программного обеспечения перед компиляцией. Инструмент анализирует действия исходного кода (runtime-resolved вызовы, taint-потоки, сисколы) и вычисляет приблизительный "рейтинг подозрительности" (behavioral threat score), который EDR или античит могли бы присвоить скомпилированному бинарному файлу на основе его действий.

TraceQL помогает разработчикам EDR/античитов создавать точные сигнатуры, находить техники обхода и оценивать, как их собственные проекты будут восприниматься системами защиты после компиляции. Результаты анализа экспортируются в JSON, Sigma YAML, SARIF, Mermaid и Graphviz.

## Quick start

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
./build/traceql_merge --help
./traceql --help
```

## Documentation

| Guide | Covers |
| :--- | :--- |
| [Building](docs/building.md) | Prerequisites, CMake build targets, running tests, bundled dependencies |
| [Usage and CLI](docs/usage.md) | Incremental `compile_commands.json` scans, Clang/LLVM plugin flags, PR diff mode |
| [Analysis and formats](docs/analysis-and-formats.md) | AST/IR detection stages, taint and lock checks, datasets, SARIF/Sigma/graph outputs |
