// pydbg LLVM instrumentation backend
#pragma once
/*
 * =========================================================================
 *  ClangToIRConverter — clang C++ AST → LLVM IR
 * =========================================================================
 *  Parses C source through the clang C++ frontend (clang::tooling) and
 *  generates equivalent LLVM IR using the LLVM C++ IRBuilder API.
 *
 *  Fully static: links the clang static component libraries; the resulting
 *  extension has NO libclang.dll dependency.
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

namespace clang {
class ASTContext;
class Expr;
class Stmt;
class FunctionDecl;
class VarDecl;
class ReturnStmt;
class IfStmt;
class WhileStmt;
class BinaryOperator;
class CallExpr;
class IntegerLiteral;
class DeclRefExpr;
class UnaryOperator;
class QualType;
}

/* The AST frontend action and its diagnostic capturer (both defined in the
 * .cpp) are friends so they can feed parse errors back into the converter. */
class ClangToIRFrontendAction;
class ClangToIRErrorConsumer;

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

private:
    friend class ClangToIRFrontendAction;
    friend class ClangToIRErrorConsumer;
    friend class ClangToIRConsumer;

    /* Called by the frontend action's AST consumer once the TU is parsed. */
    void convertTranslationUnit(clang::ASTContext& ctx);

    /* Record a parse error (first error wins). */
    void setParseError(const std::string& msg) {
        if (lastError_.empty()) lastError_ = "Parse error: " + msg;
    }

    /* ── IR emission ─────────────────────────────────────────────────── */
    void emitFunction(clang::FunctionDecl* fd);
    void emitStmt(clang::Stmt* s);
    void emitReturnStmt(clang::ReturnStmt* ret);
    void emitIfStmt(clang::IfStmt* ifs);
    void emitWhileStmt(clang::WhileStmt* ws);
    void emitVarDecl(clang::VarDecl* vd);
    llvm::Value* emitExpr(clang::Expr* e);
    llvm::Value* emitBinaryOperator(clang::BinaryOperator* bin);
    llvm::Value* emitCallExpr(clang::CallExpr* call);
    llvm::Value* emitIntegerLiteral(clang::IntegerLiteral* lit);
    llvm::Value* emitDeclRefExpr(clang::DeclRefExpr* ref);
    llvm::Value* emitUnaryOperator(clang::UnaryOperator* un);

    /* ── Helpers ─────────────────────────────────────────────────────── */
    llvm::Type* getLLVMType(clang::QualType qt);
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

    /* ── Target triple (empty = host) ─────────────────────────────────── */
    std::string targetTriple_;

    /* ── Error tracking ──────────────────────────────────────────────── */
    std::string lastError_;
};
