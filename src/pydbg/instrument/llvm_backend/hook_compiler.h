// pydbg LLVM instrumentation backend — HookCompiler public API
// 骨架：仅验证工具链链接。Task 2 移植全量实现。
#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "external_symbol.h"

class HookCompiler {
public:
    explicit HookCompiler(const std::string& targetTriple);
    HookCompiler(const HookCompiler&) = delete;
    HookCompiler& operator=(const HookCompiler&) = delete;

    std::vector<uint8_t> compile(const std::string& cSource,
                                  const ExternalSymbolTable& symbols);
    const std::string& getLastError() const { return lastError_; }
    static std::string resolveTriple(const std::string& arch);

private:
    std::string targetTriple_;
    std::string lastError_;
};
