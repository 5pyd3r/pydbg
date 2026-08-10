// pydbg LLVM instrumentation backend — shared ExternalSymbolTable typedef
#pragma once

#include <map>
#include <string>
#include <cstdint>

using ExternalSymbolTable = std::map<std::string, uint64_t>;
