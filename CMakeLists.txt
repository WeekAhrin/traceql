cmake_minimum_required(VERSION 3.20)
project(TraceQL LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

enable_testing()

# Third-party dependencies (autonomous inside tools/traceql/third_party)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/yaml-cpp)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(yaml-cpp PRIVATE -include cstdint)
endif()

add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann/include)

add_library(concurrentqueue INTERFACE)
target_include_directories(concurrentqueue INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/concurrentqueue)

# Common include directories for TraceQL
set(TRACEQL_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

# 1. Platform
add_library(TraceQLPlatform STATIC
    platform/header_classifier.cpp
)
target_include_directories(TraceQLPlatform PUBLIC ${TRACEQL_INCLUDE_DIRS})

# 2. Symbols
add_library(TraceQLSymbols STATIC
    symbols/binary_symbol_parser.cpp
    symbols/remote_symbol_resolver.cpp
)
target_include_directories(TraceQLSymbols PUBLIC ${TRACEQL_INCLUDE_DIRS})

# 3. Analysis (Behavior, DatasetLoader, Entropy, Lock, Taint, PointsTo)
add_library(TraceQLAnalysis STATIC
    analysis/behavior_classifier.cpp
    analysis/dataset_loader.cpp
    analysis/entropy_analyzer.cpp
    analysis/lock_analyzer.cpp
    base/aho_corasick.cpp
    base/fixpoint_solver.cpp
    safety/points_to.cpp
    safety/taint_tracker.cpp
)
target_include_directories(TraceQLAnalysis PUBLIC ${TRACEQL_INCLUDE_DIRS})
target_link_libraries(TraceQLAnalysis PUBLIC
    TraceQLPlatform
    nlohmann_json
    concurrentqueue
    yaml-cpp::yaml-cpp
)

# 4. Patterns
add_library(TraceQLPatterns STATIC
    patterns/call_pattern.cpp
    patterns/behavior_rule_emitter.cpp
)
target_include_directories(TraceQLPatterns PUBLIC ${TRACEQL_INCLUDE_DIRS})
target_link_libraries(TraceQLPatterns PUBLIC
    TraceQLPlatform
    TraceQLAnalysis
    nlohmann_json
    yaml-cpp::yaml-cpp
)

# 5. Aggregator
add_library(TraceQLAggregator STATIC
    aggregator/project_aggregator.cpp
)
target_include_directories(TraceQLAggregator PUBLIC ${TRACEQL_INCLUDE_DIRS})
target_link_libraries(TraceQLAggregator PUBLIC
    TraceQLPatterns
    TraceQLAnalysis
    TraceQLPlatform
    nlohmann_json
)

# 6. IR Core & Pass
add_library(TraceQLIRCore STATIC
    ir/ir_asm_classifier.cpp
)
target_include_directories(TraceQLIRCore PUBLIC ${TRACEQL_INCLUDE_DIRS})

add_library(TraceQLIR SHARED
    ir/ir_pass.cpp
)
target_include_directories(TraceQLIR PUBLIC ${TRACEQL_INCLUDE_DIRS})
target_link_libraries(TraceQLIR PRIVATE
    TraceQLPatterns
    TraceQLAnalysis
    TraceQLPlatform
    TraceQLIRCore
)
set_target_properties(TraceQLIR PROPERTIES PREFIX "")

# 7. Clang Plugin
add_library(TraceQL SHARED
    plugin/ast_visitor.cpp
    plugin/clang_plugin.cpp
)
target_include_directories(TraceQL PUBLIC ${TRACEQL_INCLUDE_DIRS})
target_link_libraries(TraceQL PRIVATE
    TraceQLPlatform
    TraceQLSymbols
    TraceQLAnalysis
    TraceQLPatterns
)
set_target_properties(TraceQL PROPERTIES PREFIX "")

# 8. CLI Merge / Analyzer
add_executable(traceql_merge
    aggregator/merge_main.cpp
)
target_include_directories(traceql_merge PRIVATE ${TRACEQL_INCLUDE_DIRS})
target_link_libraries(traceql_merge PRIVATE
    TraceQLAggregator
    TraceQLPatterns
    TraceQLAnalysis
    TraceQLPlatform
)

# 9. Tests
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/googletest/CMakeLists.txt")
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/googletest googletest)
else()
    find_package(GTest REQUIRED)
endif()

add_executable(test_traceql
    tests/test_traceql.cpp
)
target_include_directories(test_traceql PRIVATE ${TRACEQL_INCLUDE_DIRS})
target_link_libraries(test_traceql PRIVATE
    TraceQLPlatform
    TraceQLSymbols
    TraceQLAnalysis
    TraceQLPatterns
    TraceQLAggregator
    TraceQLIRCore
    GTest::gtest_main
    GTest::gmock
)

add_test(NAME TraceQLTests COMMAND test_traceql)
