#pragma once

#include "llvm/IR/PassManager.h"

namespace traceql {

    /// @brief LLVM New Pass Manager module pass that inspects post-optimization IR for
    ///        inline-asm syscalls/anti-analysis, inttoptr/indirect calls, and high-entropy globals.
    class RuntimeDetectorIRPass : public llvm::PassInfoMixin<RuntimeDetectorIRPass> {
      public:
        llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);
    };

} // namespace traceql
