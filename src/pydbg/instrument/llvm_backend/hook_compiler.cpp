// 骨架实现：验证 MSVC + LLVM 头文件 + LLVM 库链接（Task 2 全量移植）
#include "hook_compiler.h"

HookCompiler::HookCompiler(const std::string& targetTriple)
    : targetTriple_(targetTriple) {}

std::vector<uint8_t> HookCompiler::compile(const std::string& cSource,
                                            const ExternalSymbolTable& symbols) {
    (void)cSource; (void)symbols;
    lastError_ = "skeleton";
    return {0x90, 0xC3};  // nop; ret
}

std::string HookCompiler::resolveTriple(const std::string& arch) {
    if (arch == "x86_64") return "x86_64-pc-windows-msvc";
    if (arch == "x86")    return "i686-pc-windows-msvc";
    return arch;
}
