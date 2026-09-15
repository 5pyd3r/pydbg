// pydbg LLVM instrumentation backend
#pragma once
/*
 * =========================================================================
 *  TargetCodeGen — x86/x64 machine code generator
 * =========================================================================
 *
 *  Uses LLVM's TargetMachine to compile LLVM IR into native machine code for
 *  the x86/x86_64 Windows targets pydbg instruments.
 *
 *  This class:
 *    1. Accepts an x86/x86_64 target triple (or "host")
 *    2. Compiles IR → object file → extracts .text section
 *    3. Returns raw machine code bytes for the target arch
 *
 *  The output can be:
 *    - Dumped as hex to stdout
 *    - Written to a binary file
 * =========================================================================
 */

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

#include "external_symbol.h"

namespace llvm {
    class Module;
    class TargetMachine;
namespace object {
    class ObjectFile;
}
}

class TargetCodeGen {
public:
    explicit TargetCodeGen(const std::string& targetTriple);
    ~TargetCodeGen();

    TargetCodeGen(const TargetCodeGen&) = delete;
    TargetCodeGen& operator=(const TargetCodeGen&) = delete;

    /*
     * Compile LLVM IR → machine code (.text section).
     * External calls remain as relocation entries.
     */
    std::vector<uint8_t> compile(llvm::Module* module);

    /*
     * Compile LLVM IR → machine code with external symbols pre-resolved.
     *
     * After generating the object file, this method:
     *   1. Scans all relocations in .text
     *   2. For each relocation referencing an external symbol
     *   3. Looks up the address in `symbols`
     *   4. Patches the machine code bytes in-place
     *
     * The output is a flat byte array of native machine code with all
     * external calls baked in — zero relocations, zero runtime resolution.
     *
     * @param module       The LLVM module
     * @param symbols      Map of symbol name → absolute address
     * @param baseAddress  Address where the emitted machine code will be
     *                     loaded in the target process. Used to compute
     *                     PC-relative relocation targets so absolute calls
     *                     land correctly once injected. Defaults to 0, which
     *                     keeps previous behavior (caller must re-base).
     * @return             Patched machine code bytes, empty on error
     */
    std::vector<uint8_t> compile(llvm::Module* module,
                                  const ExternalSymbolTable& symbols,
                                  uint64_t baseAddress = 0);

    std::string getTargetTriple() const;
    std::string getTargetArchName() const;
    const std::string& getLastError() const { return lastError_; }

    /* ── Static helpers ───────────────────────────────────────────────── */

    static std::string resolveTargetTriple(const std::string& arch);
    static std::string toHex(const std::vector<uint8_t>& code,
                              int bytesPerLine = 16);
    static bool writeFile(const std::string& path,
                          const std::vector<uint8_t>& code);
    static std::string listTargets();

private:
    /* Generate object file bytes from the module */
    std::vector<uint8_t> emitObjectFile(llvm::Module* module);

    /* Apply relocations using the symbol table */
    bool applyRelocations(std::vector<uint8_t>& code,
                          llvm::object::ObjectFile* obj,
                          const ExternalSymbolTable& symbols,
                          uint64_t baseAddress);

    std::string targetTriple_;
    std::unique_ptr<llvm::TargetMachine> targetMachine_;
    std::string lastError_;
};
