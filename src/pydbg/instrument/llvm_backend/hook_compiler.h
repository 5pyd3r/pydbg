// pydbg LLVM instrumentation backend — HookCompiler public API
// Combines ClangToIRConverter (C → LLVM IR) + TargetCodeGen (IR → machine code).
#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "external_symbol.h"

class HookCompiler {
public:
    // @param targetTriple  LLVM target triple, e.g. "x86_64-pc-windows-msvc"
    explicit HookCompiler(const std::string& targetTriple);

    HookCompiler(const HookCompiler&) = delete;
    HookCompiler& operator=(const HookCompiler&) = delete;

    // Compile C source → fully resolved native machine code.
    // @param cSource      C source code string. Must contain `on_call` function.
    // @param symbols      External symbol → address mappings.
    //                     "original_func" is typically mapped to trampoline address.
    // @param baseAddress  Address where the emitted code will be loaded in the
    //                     target process (PC-relative relocations are patched
    //                     against this base). Defaults to 0 (legacy behavior).
    // @return             Machine code bytes ready for injection, empty on error.
    std::vector<uint8_t> compile(const std::string& cSource,
                                  const ExternalSymbolTable& symbols,
                                  uint64_t baseAddress = 0);

    const std::string& getLastError() const { return lastError_; }

    // Static convenience: resolve arch name → target triple
    static std::string resolveTriple(const std::string& arch);

private:
    std::string targetTriple_;
    std::string lastError_;
};
