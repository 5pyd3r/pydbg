// pydbg LLVM instrumentation backend
#pragma once
/*
 * =========================================================================
 *  ClangToIRConverter — libclang AST → LLVM IR
 * =========================================================================
 *
 *  Uses libclang to parse C source code into an AST, then walks the AST
 *  and generates equivalent LLVM IR using the LLVM C++ IRBuilder API.
 *
 *  Supported C subset:
 *    - Function declarations (including `extern`)
 *    - Function definitions with int parameters and return type
 *    - Local variable declarations (int)
 *    - Assignment expressions
 *    - Binary operations: + - * / % < > <= >= == != && ||
 *    - Unary operations: - !
 *    - Function calls
 *    - Return statements
 *    - If / else
 *    - While loops
 *    - Integer literals
 *    - Parenthesized expressions
 * =========================================================================
 */

#include <string>
#include <memory>
#include <map>
#include <vector>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Instructions.h>

#include <clang-c/Index.h>

class ClangToIRConverter {
public:
    ClangToIRConverter();
    ~ClangToIRConverter();

    /*
     * Set the target triple for the generated IR.
     * If not set, the IR will have no target triple (defaults to host).
     * Call this BEFORE convert().
     *
     * @param triple  e.g. "aarch64-unknown-linux-gnu", "x86_64-pc-windows-msvc"
     */
    void setTargetTriple(const std::string& triple) { targetTriple_ = triple; }

    /*
     * Convert C source code to an LLVM Module containing the IR.
     *
     * @param cSource   The C source code string
     * @param filename  Virtual filename for diagnostics
     * @return          Unique pointer to the LLVM Module, or nullptr on error
     */
    std::unique_ptr<llvm::Module> convert(const std::string& cSource,
                                           const std::string& filename = "input.c");

    /* Get the last error message (empty if no error) */
    const std::string& getLastError() const { return lastError_; }

    /* Get the generated IR as a human-readable string */
    std::string getIRString() const;

    /* ── AST visitor (dispatches by cursor kind) ─────────────────────── */
    llvm::Value* visitCursor(CXCursor cursor);

private:
    std::vector<llvm::Value*> visitChildrenOf(CXCursor cursor);

    /* ── Cursor handlers ─────────────────────────────────────────────── */
    llvm::Value* handleFunctionDecl(CXCursor cursor);
    llvm::Value* handleCompoundStmt(CXCursor cursor);
    llvm::Value* handleReturnStmt(CXCursor cursor);
    llvm::Value* handleBinaryOperator(CXCursor cursor);
    llvm::Value* handleCallExpr(CXCursor cursor);
    llvm::Value* handleIntegerLiteral(CXCursor cursor);
    llvm::Value* handleDeclRefExpr(CXCursor cursor);
    llvm::Value* handleDeclStmt(CXCursor cursor);
    llvm::Value* handleVarDecl(CXCursor cursor);
    llvm::Value* handleIfStmt(CXCursor cursor);
    llvm::Value* handleWhileStmt(CXCursor cursor);
    llvm::Value* handleUnaryOperator(CXCursor cursor);
    llvm::Value* handleParenExpr(CXCursor cursor);

    /* ── Helpers ─────────────────────────────────────────────────────── */
    llvm::Type* getLLVMType(CXType cxType);
    std::string getCursorSpelling(CXCursor cursor);
    std::string getTokenAtCursor(CXCursor cursor);
    llvm::Value* loadIfAlloca(llvm::Value* val);
    llvm::AllocaInst* createEntryBlockAlloca(llvm::Type* type,
                                              const std::string& name);

    /* ── LLVM state ──────────────────────────────────────────────────── */
    std::unique_ptr<llvm::LLVMContext> context_;
    std::unique_ptr<llvm::Module>      module_;
    std::unique_ptr<llvm::IRBuilder<>>  builder_;

    /* ── Current function context ────────────────────────────────────── */
    llvm::Function* currentFunction_ = nullptr;
    std::map<std::string, llvm::AllocaInst*> locals_;

    /* ── libclang state ──────────────────────────────────────────────── */
    CXTranslationUnit translationUnit_ = nullptr;

    /* ── Target triple (empty = host) ─────────────────────────────────── */
    std::string targetTriple_;

    /* ── Error tracking ──────────────────────────────────────────────── */
    std::string lastError_;
};
