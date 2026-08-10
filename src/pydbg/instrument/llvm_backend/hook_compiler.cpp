// pydbg LLVM instrumentation backend — HookCompiler implementation
#include "hook_compiler.h"
#include "clang_to_ir.h"
#include "target_codegen.h"

#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/TargetSelect.h>

// Force X86 target registration — use LLVM's standard entry points
// These are designed to prevent linker stripping of target objects
#include <llvm/Config/llvm-config.h>

extern "C" {
    void LLVMInitializeX86TargetInfo();
    void LLVMInitializeX86Target();
    void LLVMInitializeX86TargetMC();
    void LLVMInitializeX86AsmPrinter();
    void LLVMInitializeX86AsmParser();
}

HookCompiler::HookCompiler(const std::string& triple)
    : targetTriple_(triple)
{
    // One-time X86 target registration
    static bool initialized = []() {
        LLVMInitializeX86TargetInfo();
        LLVMInitializeX86Target();
        LLVMInitializeX86TargetMC();
        LLVMInitializeX86AsmPrinter();
        LLVMInitializeX86AsmParser();
        return true;
    }();
    (void)initialized;
}

std::vector<uint8_t> HookCompiler::compile(const std::string& cSource,
                                            const ExternalSymbolTable& symbols,
                                            uint64_t baseAddress) {
    lastError_.clear();

    // 1. C source → LLVM IR
    ClangToIRConverter converter;
    converter.setTargetTriple(targetTriple_);
    auto module = converter.convert(cSource, "hook_stub.c");
    if (!module) {
        lastError_ = "ClangToIR: " + converter.getLastError();
        return {};
    }

    // 2. Verify on_call exists (entry point for hook)
    auto* onCall = module->getFunction("on_call");
    if (!onCall) {
        lastError_ = "C source must define 'on_call' function";
        return {};
    }

    // 3. Detect unresolved extern symbols
    //    A function with no body (empty) that is not an LLVM intrinsic
    //    and is not the user's on_call entry point → need it in symbols
    std::vector<std::string> unresolved;
    for (auto& F : *module) {
        std::string name = F.getName().str();
        // Skip on_call (it's the user-defined entry point)
        if (name == "on_call") continue;
        // Declaration = has no function body (empty basic block list)
        if (F.empty() && !F.isIntrinsic()) {
            if (symbols.find(name) == symbols.end()) {
                unresolved.push_back(name);
            }
        }
    }
    if (!unresolved.empty()) {
        lastError_ = "Unresolved external symbol(s): ";
        for (size_t i = 0; i < unresolved.size(); i++) {
            if (i > 0) lastError_ += ", ";
            lastError_ += "'" + unresolved[i] + "'";
        }
        lastError_ += ". Add them to the symbols dict.";
        return {};
    }

    // 4. IR → machine code with symbol injection
    TargetCodeGen codegen(targetTriple_);
    auto code = codegen.compile(module.get(), symbols, baseAddress);
    if (code.empty()) {
        lastError_ = "TargetCodeGen: " + codegen.getLastError();
        return {};
    }

    return code;
}

std::string HookCompiler::resolveTriple(const std::string& arch) {
    return TargetCodeGen::resolveTargetTriple(arch);
}
