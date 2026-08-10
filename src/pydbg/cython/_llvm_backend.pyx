# _llvm_backend.pyx — Cython wrapper for HookCompiler (C++ → Python)
# Compile: meson compile (only when -Denable-llvm-instrument=true)

from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.map cimport map
from libc.stdint cimport uint8_t, uint64_t

cdef extern from "external_symbol.h":
    ctypedef map[string, uint64_t] ExternalSymbolTable

cdef extern from "hook_compiler.h":
    cdef cppclass HookCompiler:
        HookCompiler(const string& targetTriple) except +
        vector[uint8_t] compile(const string& cSource,
                                 const ExternalSymbolTable& symbols,
                                 uint64_t baseAddress)
        string getLastError()

        @staticmethod
        string resolveTriple(const string& arch)


def compile_stub(str c_source, str target_arch, dict symbols, uint64_t base_addr=0):
    """Compile C source → native machine code for target arch.

    Args:
        c_source: C source code (must define on_call function)
        target_arch: "x64" or "x86" (for pydbg), or full LLVM arch name
        symbols: dict of symbol_name → address (int)
        base_addr: address where the generated code will be loaded (0 = no base)

    Returns:
        bytes of resolved machine code.
    Raises:
        RuntimeError: if compilation fails.
    """
    # Map pydbg arch names to LLVM arch names
    arch_map = {'x64': 'x86_64', 'x86': 'x86'}
    cdef str llvm_arch = arch_map.get(target_arch, target_arch)

    cdef string cpp_source = c_source.encode('utf-8')
    cdef string cpp_arch = llvm_arch.encode('utf-8')
    cdef string triple = HookCompiler.resolveTriple(cpp_arch)

    cdef ExternalSymbolTable sym_map
    for name, addr in symbols.items():
        sym_map[name.encode('utf-8')] = <uint64_t>addr

    cdef HookCompiler* compiler = new HookCompiler(triple)
    cdef vector[uint8_t] code
    try:
        code = compiler.compile(cpp_source, sym_map, <uint64_t>base_addr)
        if code.empty():
            raise RuntimeError(compiler.getLastError().decode('utf-8'))
        return bytes(<char*>code.data())[:code.size()]
    finally:
        del compiler
