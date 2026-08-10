// pydbg LLVM instrumentation backend
/*
 * =========================================================================
 *  TargetCodeGen — Implementation
 * =========================================================================
 *
 *  Pipeline:
 *
 *    LLVM Module
 *      → TargetMachine::addPassesToEmitFile  (CGFT_ObjectFile)
 *      → object file bytes (ELF / MachO / COFF)
 *      → extract .text section
 *      → scan .rela.text relocations
 *      → patch external symbol addresses in-place
 *      → flat machine code bytes (zero relocations)
 * =========================================================================
 */

#include "target_codegen.h"

#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/MachO.h>
#include <llvm/Object/COFF.h>

#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstring>

/* ======================================================================
 *  One-time initialization of ALL LLVM targets
 * ====================================================================== */

namespace {
    struct AllTargetsInit {
        AllTargetsInit() {
            llvm::InitializeAllTargetInfos();
            llvm::InitializeAllTargets();
            llvm::InitializeAllTargetMCs();
            llvm::InitializeAllAsmPrinters();
            llvm::InitializeAllAsmParsers();
        }
    };
    static AllTargetsInit g_allTargetsInit;
}

/* ======================================================================
 *  Architecture-specific relocation patching
 * ====================================================================== *
 *
 *  When LLVM emits a `call host_print` for an undefined external, it
 *  generates:
 *
 *    x86_64:   E8 00 00 00 00       (CALL rel32, offset=0 placeholder)
 *              + R_X86_64_PLT32 relocation @ offset 1
 *
 *    ARM64:    00 00 00 94           (BL, imm26=0 placeholder)
 *              + R_AARCH64_CALL26 relocation @ offset 0
 *
 *    ARM32:    00 00 00 EB           (BL, imm24=0 placeholder)
 *              + R_ARM_CALL relocation @ offset 0
 *
 *  We patch the placeholder with the real address from the symbol table.
 *
 *  For x86_64:  offset = (target - (section_base + reloc_offset + 4))
 *               Patch 4 bytes at reloc_offset (little-endian i32)
 *
 *  For ARM64:   offset = (target - (section_base + reloc_offset)) / 4
 *               Patch bits [25:0] of the instruction at reloc_offset
 *
 *  For ARM32:   offset = (target - (section_base + reloc_offset + 8)) / 4
 *               Patch bits [23:0] of the instruction at reloc_offset
 * ====================================================================== */

static uint64_t readLE32(const uint8_t* p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24);
}

static void writeLE32(uint8_t* p, uint32_t v) {
    p[0] = v & 0xFF;
    p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF;
    p[3] = (v >> 24) & 0xFF;
}

static uint32_t readBE32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void writeBE32(uint8_t* p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

/*
 * Patch a single relocation in the .text section.
 *
 * Returns true on success, false if the relocation type is unsupported.
 */
static bool patchOneReloc(std::vector<uint8_t>& code,
                           uint64_t offset,
                           uint32_t relocType,
                           uint64_t symbolAddr,
                           uint64_t sectionAddr,
                           const llvm::Triple& triple) {
    if (offset + 4 > code.size()) return false;

    uint8_t* patch = code.data() + offset;
    int arch = triple.getArch();

    /* ── x86 / x86_64 ──────────────────────────────────────────────── */
    if (arch == llvm::Triple::x86_64 || arch == llvm::Triple::x86) {
        /* R_X86_64_PLT32 / R_X86_64_PC32 / R_386_PC32
         * The relocation stores a 32-bit signed PC-relative offset.
         * offset = symbol - (section_base + reloc_offset + 4) */
        int64_t pc = sectionAddr + offset + 4;
        int64_t delta = (int64_t)symbolAddr - pc;

        if (delta < INT32_MIN || delta > INT32_MAX) {
            return false; /* Target out of 32-bit range */
        }
        writeLE32(patch, (uint32_t)(int32_t)delta);
        return true;
    }

    /* ── AArch64 ────────────────────────────────────────────────────── */
    if (arch == llvm::Triple::aarch64 ||
        arch == llvm::Triple::aarch64_be) {
        /* R_AARCH64_CALL26 — BL / B instruction, 26-bit signed offset
         * offset = (symbol - pc) / 4
         * Patch bits [25:0] of the 32-bit instruction. */
        int64_t pc = sectionAddr + offset;
        int64_t delta = (int64_t)symbolAddr - pc;

        if (delta % 4 != 0) return false;
        int64_t imm26 = delta / 4;
        if (imm26 < -(1 << 25) || imm26 >= (1 << 25)) return false;

        uint32_t insn;
        if (triple.isLittleEndian()) {
            insn = (uint32_t)readLE32(patch);
            insn = (insn & 0xFC000000) | (uint32_t)(imm26 & 0x03FFFFFF);
            writeLE32(patch, insn);
        } else {
            insn = readBE32(patch);
            insn = (insn & 0xFC000000) | (uint32_t)(imm26 & 0x03FFFFFF);
            writeBE32(patch, insn);
        }
        return true;
    }

    /* ── ARM32 ──────────────────────────────────────────────────────── */
    if (arch == llvm::Triple::arm || arch == llvm::Triple::thumb) {
        /* R_ARM_CALL — BL instruction, 24-bit signed offset
         * offset = (symbol - pc - 8) / 4   (ARM pipeline: PC = current + 8)
         * Patch bits [23:0] of the 32-bit instruction. */
        int64_t pc = sectionAddr + offset + 8;  /* ARM pipeline offset */
        int64_t delta = (int64_t)symbolAddr - pc;

        if (delta % 4 != 0) return false;
        int64_t imm24 = delta / 4;
        if (imm24 < -(1 << 23) || imm24 >= (1 << 23)) return false;

        uint32_t insn;
        if (triple.isLittleEndian()) {
            insn = (uint32_t)readLE32(patch);
            insn = (insn & 0xFF000000) | (uint32_t)(imm24 & 0x00FFFFFF);
            writeLE32(patch, insn);
        } else {
            insn = readBE32(patch);
            insn = (insn & 0xFF000000) | (uint32_t)(imm24 & 0x00FFFFFF);
            writeBE32(patch, insn);
        }
        return true;
    }

    /* ── RISC-V ─────────────────────────────────────────────────────── */
    if (arch == llvm::Triple::riscv64 || arch == llvm::Triple::riscv32) {
        /* R_RISCV_CALL / R_RISCV_CALL_PLT — JAL offset
         * 32-bit instruction: imm[20|10:1|11|19:12] in bits [31:12]
         * For simplicity, emit a 6-byte sequence: AUIPC + JALR
         * But LLVM already emits AUIPC+JALR pair. We patch both.
         *
         * Instruction at offset:   AUIPC rd, imm[31:12]
         * Instruction at offset+4: JALR  rd, rd, imm[11:0]
         *
         * We need to split the 32-bit PC-relative delta into
         * upper 20 bits (AUIPC) and lower 12 bits (JALR). */
        if (offset + 8 > code.size()) return false;

        int64_t pc = sectionAddr + offset;
        int64_t delta = (int64_t)symbolAddr - pc;

        uint32_t hi20 = (uint32_t)((delta + 0x800) >> 12);  /* round */
        int32_t  lo12 = (int32_t)(delta - ((int64_t)hi20 << 12));

        uint32_t auipc, jalr;
        if (triple.isLittleEndian()) {
            auipc = (uint32_t)readLE32(patch);
            auipc = (auipc & 0x00000FFF) | (hi20 << 12);
            writeLE32(patch, auipc);

            jalr = (uint32_t)readLE32(patch + 4);
            jalr = (jalr & 0x000FFFFF) | ((uint32_t)(lo12 & 0xFFF) << 20);
            writeLE32(patch + 4, jalr);
        } else {
            auipc = readBE32(patch);
            auipc = (auipc & 0x00000FFF) | (hi20 << 12);
            writeBE32(patch, auipc);

            jalr = readBE32(patch + 4);
            jalr = (jalr & 0x000FFFFF) | ((uint32_t)(lo12 & 0xFFF) << 20);
            writeBE32(patch + 4, jalr);
        }
        return true;
    }

    return false; /* Unsupported architecture */
}

/* ======================================================================
 *  resolveTargetTriple
 * ====================================================================== */

std::string TargetCodeGen::resolveTargetTriple(const std::string& arch) {
    if (arch.empty() || arch == "host") {
        return llvm::sys::getProcessTriple();
    }

    /* pydbg instruments Windows targets only. The host LLVM build may report
     * a Linux triple (→ SysV calling convention), so pin x86/x86_64 to the
     * Windows MSVC ABI: Win64 passes int args in RCX/RDX, Win32 on the stack. */
    llvm::Triple hostTriple(llvm::sys::getProcessTriple());

    if (arch == "x86" || arch == "i686" || arch == "i386")
        return "i686-pc-windows-msvc";
    if (arch == "x86_64" || arch == "amd64" || arch == "x64")
        return "x86_64-pc-windows-msvc";
    if (arch == "arm64" || arch == "aarch64") {
        if (hostTriple.isOSDarwin())  return "aarch64-apple-darwin";
        if (hostTriple.isOSWindows()) return "aarch64-pc-windows-msvc";
        return "aarch64-unknown-linux-gnu";
    }
    if (arch == "arm32" || arch == "arm" || arch == "armv7") {
        if (hostTriple.isOSDarwin()) return "arm-apple-darwin";
        return "arm-unknown-linux-gnueabihf";
    }
    if (arch == "riscv64") return "riscv64-unknown-linux-gnu";
    if (arch == "riscv32") return "riscv32-unknown-linux-gnu";

    return arch; /* Assume full triple */
}

/* ======================================================================
 *  Constructor / Destructor
 * ====================================================================== */

TargetCodeGen::TargetCodeGen(const std::string& targetTriple)
    : targetTriple_(targetTriple) {

    std::string error;
    const llvm::Target* target =
        llvm::TargetRegistry::lookupTarget(targetTriple_, error);

    if (!target) {
        lastError_ = "Unknown target '" + targetTriple_ + "': " + error;
        return;
    }

    llvm::TargetOptions options;
    targetMachine_.reset(target->createTargetMachine(
        targetTriple_, "generic", "", options, llvm::Reloc::Static));

    if (!targetMachine_) {
        lastError_ = "Failed to create TargetMachine for " + targetTriple_;
    }
}

TargetCodeGen::~TargetCodeGen() = default;

/* ======================================================================
 *  emitObjectFile — IR → object file bytes
 * ====================================================================== */

std::vector<uint8_t> TargetCodeGen::emitObjectFile(llvm::Module* module) {
    if (!targetMachine_) {
        lastError_ = "TargetMachine not initialized";
        return {};
    }

    module->setTargetTriple(targetTriple_);
    module->setDataLayout(targetMachine_->createDataLayout());

    llvm::legacy::PassManager pm;
    llvm::SmallVector<char, 0> buf;
    llvm::raw_svector_ostream os(buf);

    if (targetMachine_->addPassesToEmitFile(pm, os, nullptr,
                                             llvm::CGFT_ObjectFile)) {
        lastError_ = "Cannot emit object file for " + targetTriple_;
        return {};
    }

    pm.run(*module);

    if (buf.empty()) {
        lastError_ = "Code generation produced empty output";
        return {};
    }

    return std::vector<uint8_t>(buf.begin(), buf.end());
}

/* ======================================================================
 *  applyRelocations — patch external symbol addresses into .text
 * ====================================================================== */

bool TargetCodeGen::applyRelocations(std::vector<uint8_t>& code,
                                      llvm::object::ObjectFile* obj,
                                      const ExternalSymbolTable& symbols,
                                      uint64_t baseAddress) {
    llvm::Triple triple(targetTriple_);
    int patched = 0;
    std::vector<std::string> unresolved;

    /* Find the .text section base address.
     * COFF object sections report sec.getAddress() == 0, which is only
     * correct when the code is injected at address 0. Use the caller's
     * baseAddress (the real address where the code will be loaded) so that
     * PC-relative relocation targets resolve to the correct absolute address. */
    uint64_t textAddr = 0;
    for (const auto& sec : obj->sections()) {
        auto name = sec.getName();
        if (name && (*name == ".text" || name->ends_with("text"))) {
            textAddr = baseAddress;
            break;
        }
    }

    /* Iterate all relocations in the object */
    for (const auto& sec : obj->sections()) {
        auto secName = sec.getName();
        if (!secName) continue;

        for (const auto& reloc : sec.relocations()) {
            auto sym = reloc.getSymbol();
            auto nameOrErr = sym->getName();
            if (!nameOrErr) continue;

            std::string symName = nameOrErr->str();

            /* Skip section symbols, debug symbols, etc. */
            auto flagsOrErr = sym->getFlags();
            if (!flagsOrErr) continue;
            uint32_t flags = *flagsOrErr;
            if (!(flags & llvm::object::SymbolRef::SF_Undefined))
                continue;

            auto it = symbols.find(symName);
            if (it == symbols.end()) {
                /* Symbol declared extern but not resolved — collect for error */
                unresolved.push_back(symName);
                continue;
            }

            uint64_t symAddr = it->second;
            uint64_t relocOffset = reloc.getOffset();
            uint32_t relocType   = reloc.getType();

            if (patchOneReloc(code, relocOffset, relocType,
                              symAddr, textAddr, triple)) {
                patched++;
            } else {
                lastError_ = "Unsupported relocation type " +
                             std::to_string(relocType) +
                             " for symbol '" + symName + "'";
                /* Fail fast: a partially-patched .text would silently ship
                 * E8 00 00 00 00 placeholders. Returning false lets compile()
                 * take the error path (lastError_ is non-empty). */
                return false;
            }
        }
    }

    /* Report unresolved extern symbols as a clear error */
    if (!unresolved.empty()) {
        lastError_ = "Unresolved external symbol(s): ";
        for (size_t i = 0; i < unresolved.size(); i++) {
            if (i > 0) lastError_ += ", ";
            lastError_ += "'" + unresolved[i] + "'";
        }
        lastError_ += ". Add them to the symbols dict.";
        return false;
    }

    return patched > 0;
}

/* ======================================================================
 *  compile (without symbol injection) — raw .text with relocations
 * ====================================================================== */

std::vector<uint8_t> TargetCodeGen::compile(llvm::Module* module) {
    lastError_.clear();

    auto objBytes = emitObjectFile(module);
    if (objBytes.empty()) return {};

    auto memBuf = llvm::MemoryBuffer::getMemBuffer(
        llvm::StringRef(reinterpret_cast<const char*>(objBytes.data()),
                        objBytes.size()),
        "", false);

    auto objOrErr = llvm::object::ObjectFile::createObjectFile(
        memBuf->getMemBufferRef());

    if (!objOrErr) {
        lastError_ = "Failed to parse generated object file";
        return {};
    }

    /* Extract .text */
    for (const auto& sec : (*objOrErr)->sections()) {
        auto name = sec.getName();
        if (!name) continue;
        if (*name == ".text" || name->ends_with("text")) {
            auto contents = sec.getContents();
            if (contents) {
                return std::vector<uint8_t>(contents->begin(), contents->end());
            }
        }
    }

    lastError_ = "Could not find .text section";
    return {};
}

/* ======================================================================
 *  compile (with symbol injection) — fully resolved machine code
 * ====================================================================== */

std::vector<uint8_t> TargetCodeGen::compile(llvm::Module* module,
                                              const ExternalSymbolTable& symbols,
                                              uint64_t baseAddress) {
    lastError_.clear();

    if (symbols.empty()) {
        /* No external symbols — same as the simple compile */
        return compile(module);
    }

    /* ── 1. Generate object file ────────────────────────────────────── */
    auto objBytes = emitObjectFile(module);
    if (objBytes.empty()) return {};

    /* ── 2. Parse the object file ───────────────────────────────────── */
    /* We need to keep the MemoryBuffer alive for the ObjectFile */
    auto memBuf = llvm::MemoryBuffer::getMemBuffer(
        llvm::StringRef(reinterpret_cast<const char*>(objBytes.data()),
                        objBytes.size()),
        "", false);

    auto objOrErr = llvm::object::ObjectFile::createObjectFile(
        memBuf->getMemBufferRef());

    if (!objOrErr) {
        lastError_ = "Failed to parse generated object file";
        return {};
    }

    /* ── 3. Extract .text section ───────────────────────────────────── */
    std::vector<uint8_t> code;
    llvm::object::ObjectFile* obj = objOrErr->get();

    for (const auto& sec : obj->sections()) {
        auto name = sec.getName();
        if (!name) continue;
        if (*name == ".text" || name->ends_with("text")) {
            auto contents = sec.getContents();
            if (contents) {
                code.assign(contents->begin(), contents->end());
                break;
            }
        }
    }

    if (code.empty()) {
        lastError_ = "Could not find .text section";
        return {};
    }

    /* ── 4. Patch relocations with the provided symbol addresses ────── */
    if (!applyRelocations(code, obj, symbols, baseAddress)) {
        if (!lastError_.empty()) return {};
        /* No relocations matched — that's OK, code may have no externals */
    }

    return code;
}

/* ======================================================================
 *  Getters / Static helpers
 * ====================================================================== */

std::string TargetCodeGen::getTargetTriple() const { return targetTriple_; }

std::string TargetCodeGen::getTargetArchName() const {
    llvm::Triple triple(targetTriple_);
    switch (triple.getArch()) {
        case llvm::Triple::x86:        return "x86 (32-bit)";
        case llvm::Triple::x86_64:     return "x86_64 (64-bit)";
        case llvm::Triple::aarch64:    return "aarch64 / arm64";
        case llvm::Triple::arm:        return "arm32";
        case llvm::Triple::thumb:      return "thumb (arm)";
        case llvm::Triple::riscv64:    return "riscv64";
        case llvm::Triple::riscv32:    return "riscv32";
        default:                       return triple.getArchName().str();
    }
}

std::string TargetCodeGen::toHex(const std::vector<uint8_t>& code,
                                  int bytesPerLine) {
    if (code.empty()) return "(empty)";

    std::ostringstream out;
    for (size_t i = 0; i < code.size(); i++) {
        if (i % bytesPerLine == 0) {
            if (i > 0) out << "\n";
            out << "  0x" << std::hex << std::setw(4) << std::setfill('0')
                << i << "  ";
        }
        out << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(code[i]) << " ";
    }
    out << "\n";
    return out.str();
}

bool TargetCodeGen::writeFile(const std::string& path,
                               const std::vector<uint8_t>& code) {
    std::error_code ec;
    llvm::raw_fd_ostream file(path, ec, llvm::sys::fs::OpenFlags::OF_None);
    if (ec) return false;
    file.write(reinterpret_cast<const char*>(code.data()), code.size());
    file.flush();
    return !file.has_error();
}

std::string TargetCodeGen::listTargets() {
    std::ostringstream out;
    for (const auto& target : llvm::TargetRegistry::targets()) {
        out << "  " << std::left << std::setw(20) << target.getName()
            << "  " << target.getShortDescription() << "\n";
    }
    return out.str();
}
