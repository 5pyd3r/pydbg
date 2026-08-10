// pydbg LLVM instrumentation backend
/*
 * =========================================================================
 *  ClangToIRConverter — Implementation
 * =========================================================================
 *
 *  Walks the libclang AST and emits LLVM IR using IRBuilder.
 *
 *  The visitor pattern works as follows:
 *    - clang_visitChildren() is called with a C callback
 *    - The callback invokes visitCursor() on the converter instance
 *    - visitCursor() dispatches to the appropriate handler by cursor kind
 *    - Each handler returns an llvm::Value* (expressions) or nullptr (stmts)
 *
 *  For expressions that need child values (e.g. binary operators), we use
 *  visitChildrenOf() which collects all child values into a vector.
 *
 *  For control flow statements (if, while) that need to emit IR in a
 *  specific order across multiple basic blocks, we visit children manually.
 * =========================================================================
 */

#include "clang_to_ir.h"

#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/Constants.h>

#include <iostream>
#include <sstream>

/* ======================================================================
 *  Static callback helpers for clang_visitChildren
 * ====================================================================== */

/*
 * Generic callback: calls visitCursor() on the converter and discards the
 * result.  Used for statement-level traversal (CompoundStmt, etc.).
 */
static CXChildVisitResult genericVisitor(CXCursor cursor,
                                          CXCursor /*parent*/,
                                          CXClientData clientData) {
    auto* self = static_cast<ClangToIRConverter*>(clientData);
    self->visitCursor(cursor);
    return CXChildVisit_Continue;
}

/*
 * Context for visitChildrenOf() — accumulates the LLVM Value* returned by
 * each child cursor.
 */
struct ChildCollector {
    ClangToIRConverter*           converter;
    std::vector<llvm::Value*>*    values;
};

static CXChildVisitResult collectVisitor(CXCursor cursor,
                                          CXCursor /*parent*/,
                                          CXClientData clientData) {
    auto* ctx = static_cast<ChildCollector*>(clientData);
    llvm::Value* val = ctx->converter->visitCursor(cursor);
    ctx->values->push_back(val);
    return CXChildVisit_Continue;
}

/* ======================================================================
 *  Constructor / Destructor
 * ====================================================================== */

ClangToIRConverter::ClangToIRConverter()
    : context_(std::make_unique<llvm::LLVMContext>()),
      builder_(std::make_unique<llvm::IRBuilder<>>(*context_)) {}

ClangToIRConverter::~ClangToIRConverter() {
    if (translationUnit_) {
        clang_disposeTranslationUnit(translationUnit_);
    }
}

/* ======================================================================
 *  convert() — Top-level entry point
 * ====================================================================== */

std::unique_ptr<llvm::Module> ClangToIRConverter::convert(
        const std::string& cSource,
        const std::string& filename) {
    lastError_.clear();

    /* ── Dispose previous translation unit if any ────────────────────── */
    if (translationUnit_) {
        clang_disposeTranslationUnit(translationUnit_);
        translationUnit_ = nullptr;
    }

    /* ── Create a fresh LLVM module ──────────────────────────────────── */
    module_ = std::make_unique<llvm::Module>("jit_module", *context_);

    /* ── Parse C source with libclang ────────────────────────────────── */
    CXIndex index = clang_createIndex(0, 0);
    if (!index) {
        lastError_ = "Failed to create clang index";
        return nullptr;
    }

    const char* argv[] = { "-std=c11", "-fsyntax-only" };
    int argc = 2;

    /* Use clang_createTranslationUnitFromSourceFile for in-memory source */
    CXUnsavedFile unsavedFile;
    unsavedFile.Filename = filename.c_str();
    unsavedFile.Contents = cSource.c_str();
    unsavedFile.Length = cSource.size();

    translationUnit_ = clang_parseTranslationUnit(
        index,
        filename.c_str(),
        argv, argc,
        &unsavedFile, 1,
        CXTranslationUnit_None
    );

    clang_disposeIndex(index);

    if (!translationUnit_) {
        lastError_ = "Failed to parse translation unit";
        return nullptr;
    }

    /* ── Check for parse errors ──────────────────────────────────────── */
    unsigned numDiagnostics = clang_getNumDiagnostics(translationUnit_);
    for (unsigned i = 0; i < numDiagnostics; i++) {
        CXDiagnostic diag = clang_getDiagnostic(translationUnit_, i);
        CXDiagnosticSeverity severity = clang_getDiagnosticSeverity(diag);
        if (severity == CXDiagnostic_Error || severity == CXDiagnostic_Fatal) {
            CXString msg = clang_formatDiagnostic(diag, clang_defaultDiagnosticDisplayOptions());
            lastError_ = "Parse error: ";
            lastError_ += clang_getCString(msg);
            clang_disposeString(msg);
            clang_disposeDiagnostic(diag);
            return nullptr;
        }
        clang_disposeDiagnostic(diag);
    }

    /* ── Walk the AST and generate IR ────────────────────────────────── */
    CXCursor tuCursor = clang_getTranslationUnitCursor(translationUnit_);
    clang_visitChildren(tuCursor, genericVisitor, this);

    if (!lastError_.empty()) {
        return nullptr;
    }

    /* ── Set target triple if specified ──────────────────────────────── */
    if (!targetTriple_.empty()) {
        module_->setTargetTriple(targetTriple_);
    }

    /* ── Verify the generated module ─────────────────────────────────── */
    std::string verifyErr;
    llvm::raw_string_ostream verifyStream(verifyErr);
    if (llvm::verifyModule(*module_, &verifyStream)) {
        lastError_ = "Module verification failed: " + verifyErr;
        return nullptr;
    }

    return std::move(module_);
}

/* ======================================================================
 *  getIRString() — dump the IR to a string
 * ====================================================================== */

std::string ClangToIRConverter::getIRString() const {
    if (!module_) return "<no module>";
    std::string ir;
    llvm::raw_string_ostream stream(ir);
    module_->print(stream, nullptr);
    return ir;
}

/* ======================================================================
 *  visitCursor() — Main dispatch
 * ====================================================================== */

llvm::Value* ClangToIRConverter::visitCursor(CXCursor cursor) {
    CXCursorKind kind = clang_getCursorKind(cursor);

    switch (kind) {
        case CXCursor_FunctionDecl:     return handleFunctionDecl(cursor);
        case CXCursor_CompoundStmt:     return handleCompoundStmt(cursor);
        case CXCursor_ReturnStmt:       return handleReturnStmt(cursor);
        case CXCursor_BinaryOperator:   return handleBinaryOperator(cursor);
        case CXCursor_CallExpr:         return handleCallExpr(cursor);
        case CXCursor_IntegerLiteral:   return handleIntegerLiteral(cursor);
        case CXCursor_DeclRefExpr:      return handleDeclRefExpr(cursor);
        case CXCursor_DeclStmt:         return handleDeclStmt(cursor);
        case CXCursor_VarDecl:          return handleVarDecl(cursor);
        case CXCursor_IfStmt:           return handleIfStmt(cursor);
        case CXCursor_WhileStmt:        return handleWhileStmt(cursor);
        case CXCursor_UnaryOperator:    return handleUnaryOperator(cursor);
        case CXCursor_ParenExpr:        return handleParenExpr(cursor);

        /* Type references and other bookkeeping — silently skip */
        case CXCursor_TypeRef:
        case CXCursor_UnexposedStmt:
            return nullptr;

        case CXCursor_UnexposedExpr:
            /* Try to resolve as a variable reference */
            {
                std::string name = getCursorSpelling(cursor);
                if (!name.empty()) {
                    auto it = locals_.find(name);
                    if (it != locals_.end()) {
                        return it->second;
                    }
                    llvm::Function* func = module_->getFunction(name);
                    if (func) return func;
                }
            }
            return nullptr;

        default:
            /* Try visiting children as a fallback */
            break;
    }
    return nullptr;
}

std::vector<llvm::Value*> ClangToIRConverter::visitChildrenOf(CXCursor cursor) {
    std::vector<llvm::Value*> values;
    ChildCollector collector{ this, &values };
    clang_visitChildren(cursor, collectVisitor, &collector);
    return values;
}

/* ======================================================================
 *  handleFunctionDecl
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleFunctionDecl(CXCursor cursor) {
    CXType     funcType = clang_getCursorType(cursor);
    std::string name     = getCursorSpelling(cursor);

    /* ── Build the LLVM function signature ───────────────────────────── */
    CXType       retCX    = clang_getResultType(funcType);
    llvm::Type*  retType  = getLLVMType(retCX);

    int numArgs = clang_getNumArgTypes(funcType);
    std::vector<llvm::Type*>  paramTypes;
    std::vector<std::string>  paramNames;

    for (int i = 0; i < numArgs; i++) {
        CXType argCX = clang_getArgType(funcType, i);
        paramTypes.push_back(getLLVMType(argCX));

        CXCursor argCursor = clang_Cursor_getArgument(cursor, i);
        paramNames.push_back(getCursorSpelling(argCursor));
    }

    llvm::FunctionType* ft = llvm::FunctionType::get(retType, paramTypes, false);

    /* ── Declaration only (extern) — just create the prototype ──────── */
    if (!clang_isCursorDefinition(cursor)) {
        llvm::Function* func = llvm::Function::Create(
            ft, llvm::Function::ExternalLinkage, name, module_.get());
        return func;
    }

    /* ── Definition — create function, emit body ────────────────────── */
    llvm::Function* func = module_->getFunction(name);
    if (!func) {
        func = llvm::Function::Create(
            ft, llvm::Function::ExternalLinkage, name, module_.get());
    }

    /* Name the arguments */
    unsigned idx = 0;
    for (auto& arg : func->args()) {
        arg.setName(paramNames[idx++]);
    }

    /* Create entry basic block */
    llvm::BasicBlock* entry = llvm::BasicBlock::Create(*context_, "entry", func);
    builder_->SetInsertPoint(entry);

    /* Save and replace the current function context */
    llvm::Function* prevFunc   = currentFunction_;
    auto            prevLocals = locals_;
    currentFunction_ = func;
    locals_.clear();

    /* Create allocas for parameters and store the incoming values */
    idx = 0;
    for (auto& arg : func->args()) {
        std::string argName = std::string(arg.getName());
        llvm::AllocaInst* alloca = createEntryBlockAlloca(
            arg.getType(), argName);
        builder_->CreateStore(&arg, alloca);
        locals_[argName] = alloca;
    }

    /* Visit the function body (the CompoundStmt child) */
    clang_visitChildren(cursor, [](CXCursor c, CXCursor /*parent*/, CXClientData data) {
        auto* self = static_cast<ClangToIRConverter*>(data);
        if (clang_getCursorKind(c) == CXCursor_CompoundStmt) {
            self->visitCursor(c);
        }
        return CXChildVisit_Continue;
    }, this);

    /* If the block has no terminator, add a default return */
    if (!builder_->GetInsertBlock()->getTerminator()) {
        if (retType->isVoidTy()) {
            builder_->CreateRetVoid();
        } else {
            builder_->CreateRet(llvm::ConstantInt::get(retType, 0));
        }
    }

    /* Restore previous context */
    currentFunction_ = prevFunc;
    locals_          = prevLocals;

    return func;
}

/* ======================================================================
 *  handleCompoundStmt — visit all children sequentially
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleCompoundStmt(CXCursor cursor) {
    clang_visitChildren(cursor, genericVisitor, this);
    return nullptr;
}

/* ======================================================================
 *  handleReturnStmt
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleReturnStmt(CXCursor cursor) {
    auto children = visitChildrenOf(cursor);
    if (children.empty() || !children[0]) {
        return builder_->CreateRetVoid();
    }
    llvm::Value* retVal = loadIfAlloca(children[0]);
    return builder_->CreateRet(retVal);
}

/* ======================================================================
 *  handleBinaryOperator
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleBinaryOperator(CXCursor cursor) {
    auto children = visitChildrenOf(cursor);
    if (children.size() != 2 || !children[0] || !children[1]) {
        lastError_ = "Binary operator: expected 2 operands";
        return nullptr;
    }

    llvm::Value* lhs = children[0];
    llvm::Value* rhs = children[1];

    std::string op = getTokenAtCursor(cursor);

    /* ── Assignment ──────────────────────────────────────────────────── */
    if (op == "=") {
        rhs = loadIfAlloca(rhs);
        builder_->CreateStore(rhs, lhs);
        return rhs;
    }

    /* ── Load operands (auto-deref allocas) ─────────────────────────── */
    lhs = loadIfAlloca(lhs);
    rhs = loadIfAlloca(rhs);

    /* ── Arithmetic ──────────────────────────────────────────────────── */
    if (op == "+")  return builder_->CreateAdd(lhs, rhs, "addtmp");
    if (op == "-")  return builder_->CreateSub(lhs, rhs, "subtmp");
    if (op == "*")  return builder_->CreateMul(lhs, rhs, "multmp");
    if (op == "/")  return builder_->CreateSDiv(lhs, rhs, "divtmp");
    if (op == "%")  return builder_->CreateSRem(lhs, rhs, "remtmp");

    /* ── Comparison ──────────────────────────────────────────────────── */
    if (op == "<")  return builder_->CreateICmpSLT(lhs, rhs, "cmptmp");
    if (op == ">")  return builder_->CreateICmpSGT(lhs, rhs, "cmptmp");
    if (op == "<=") return builder_->CreateICmpSLE(lhs, rhs, "cmptmp");
    if (op == ">=") return builder_->CreateICmpSGE(lhs, rhs, "cmptmp");
    if (op == "==") return builder_->CreateICmpEQ(lhs, rhs, "cmptmp");
    if (op == "!=") return builder_->CreateICmpNE(lhs, rhs, "cmptmp");

    /* ── Logical (bitwise for integers) ──────────────────────────────── */
    if (op == "&&") return builder_->CreateAnd(lhs, rhs, "andtmp");
    if (op == "||") return builder_->CreateOr(lhs, rhs, "ortmp");

    lastError_ = "Unsupported binary operator: " + op;
    return nullptr;
}

/* ======================================================================
 *  handleCallExpr
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleCallExpr(CXCursor cursor) {
    auto children = visitChildrenOf(cursor);
    if (children.empty()) {
        lastError_ = "CallExpr: no children";
        return nullptr;
    }

    /* First child is the callee (function pointer or reference) */
    llvm::Value*  callee = children[0];
    llvm::Function* func = llvm::dyn_cast<llvm::Function>(callee);
    if (!func) {
        lastError_ = "CallExpr: callee is not a function";
        return nullptr;
    }

    /* Remaining children are the arguments */
    std::vector<llvm::Value*> args;
    for (size_t i = 1; i < children.size(); i++) {
        args.push_back(loadIfAlloca(children[i]));
    }

    /* Match argument count */
    if (func->arg_size() != args.size()) {
        lastError_ = "CallExpr: argument count mismatch for " +
                     func->getName().str();
        return nullptr;
    }

    /* Don't name void calls */
    if (func->getReturnType()->isVoidTy()) {
        return builder_->CreateCall(func, args);
    }
    return builder_->CreateCall(func, args, "calltmp");
}

/* ======================================================================
 *  handleIntegerLiteral
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleIntegerLiteral(CXCursor cursor) {
    /*
     * libclang doesn't expose the literal value directly through the C API.
     * We tokenize the cursor range and parse the number.
     */
    CXSourceRange range = clang_getCursorExtent(cursor);
    CXToken*      tokens = nullptr;
    unsigned      numTokens = 0;
    clang_tokenize(translationUnit_, range, &tokens, &numTokens);

    long long value = 0;
    for (unsigned i = 0; i < numTokens; i++) {
        CXTokenKind kind = clang_getTokenKind(tokens[i]);
        if (kind == CXToken_Literal) {
            CXString spelling = clang_getTokenSpelling(translationUnit_, tokens[i]);
            value = std::stoll(clang_getCString(spelling));
            clang_disposeString(spelling);
            break;
        }
    }
    clang_disposeTokens(translationUnit_, tokens, numTokens);

    return llvm::ConstantInt::get(llvm::Type::getInt32Ty(*context_), value, true);
}

/* ======================================================================
 *  handleDeclRefExpr — reference to a variable or function
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleDeclRefExpr(CXCursor cursor) {
    std::string name = getCursorSpelling(cursor);

    /* Check if it refers to a function */
    CXCursor referenced = clang_getCursorReferenced(cursor);
    if (clang_getCursorKind(referenced) == CXCursor_FunctionDecl) {
        llvm::Function* func = module_->getFunction(name);
        if (func) return func;
    }

    /* Check local variables */
    auto it = locals_.find(name);
    if (it != locals_.end()) {
        return it->second;   /* Return the alloca (lvalue) */
    }

    /* Check functions as a fallback */
    llvm::Function* func = module_->getFunction(name);
    if (func) return func;

    lastError_ = "Unknown identifier: " + name;
    return nullptr;
}

/* ======================================================================
 *  handleDeclStmt — contains one or more VarDecl children
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleDeclStmt(CXCursor cursor) {
    clang_visitChildren(cursor, genericVisitor, this);
    return nullptr;
}

/* ======================================================================
 *  handleVarDecl — local variable with optional initializer
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleVarDecl(CXCursor cursor) {
    std::string name = getCursorSpelling(cursor);
    CXType      cxType = clang_getCursorType(cursor);
    llvm::Type* type   = getLLVMType(cxType);

    llvm::AllocaInst* alloca = createEntryBlockAlloca(type, name);
    locals_[name] = alloca;

    /* Visit children — the initializer expression (if any) is a child
       that is NOT a TypeRef.  We pass the alloca through a context struct
       so the C callback can store the initializer to the correct address. */
    struct VarDeclCtx {
        ClangToIRConverter* self;
        llvm::AllocaInst*   alloca;
    };

    VarDeclCtx ctx{ this, alloca };
    clang_visitChildren(cursor, [](CXCursor c, CXCursor /*parent*/, CXClientData data) {
        auto* ctx = static_cast<VarDeclCtx*>(data);
        CXCursorKind kind = clang_getCursorKind(c);
        if (kind != CXCursor_TypeRef) {
            llvm::Value* init = ctx->self->visitCursor(c);
            if (init) {
                init = ctx->self->loadIfAlloca(init);
                ctx->self->builder_->CreateStore(init, ctx->alloca);
            }
        }
        return CXChildVisit_Continue;
    }, &ctx);

    return alloca;
}

/* ======================================================================
 *  handleIfStmt
 *
 *  if (cond) { then } else { else }
 *
 *  Generates:
 *    entry:  <evaluate cond>
 *            br i1 %cond, %if.then, %if.else   (or %if.end if no else)
 *    if.then: <then body>
 *            br %if.end
 *    if.else: <else body>        (omitted if no else)
 *            br %if.end
 *    if.end:  <continue>
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleIfStmt(CXCursor cursor) {
    llvm::Function* func = currentFunction_;

    llvm::BasicBlock* thenBB  = llvm::BasicBlock::Create(*context_, "if.then", func);
    llvm::BasicBlock* elseBB  = llvm::BasicBlock::Create(*context_, "if.else");
    llvm::BasicBlock* mergeBB = llvm::BasicBlock::Create(*context_, "if.end");

    /*
     * We need to visit children in order: condition, then-body, else-body.
     * clang_visitChildren visits them left-to-right, which is exactly
     * what we need, but we must track which child we're on.
     */
    struct IfCtx {
        ClangToIRConverter* self;
        llvm::BasicBlock*   thenBB;
        llvm::BasicBlock*   elseBB;
        llvm::BasicBlock*   mergeBB;
        int                 childIdx;
        bool                hasElse;
    };

    IfCtx ctx{ this, thenBB, elseBB, mergeBB, 0, false };

    clang_visitChildren(cursor, [](CXCursor c, CXCursor /*parent*/, CXClientData data) {
        auto* ctx = static_cast<IfCtx*>(data);
        auto* self = ctx->self;

        switch (ctx->childIdx) {
            case 0: {
                /* ── Condition ──────────────────────────────────────── */
                llvm::Value* cond = self->visitCursor(c);
                cond = self->loadIfAlloca(cond);
                cond = self->builder_->CreateICmpNE(
                    cond,
                    llvm::ConstantInt::get(cond->getType(), 0),
                    "ifcond");
                /* Always branch to elseBB; if there is no else body,
                   elseBB will be wired to mergeBB below. */
                self->builder_->CreateCondBr(cond, ctx->thenBB, ctx->elseBB);
                break;
            }
            case 1: {
                /* ── Then body ──────────────────────────────────────── */
                self->builder_->SetInsertPoint(ctx->thenBB);
                self->visitCursor(c);
                if (!self->builder_->GetInsertBlock()->getTerminator()) {
                    self->builder_->CreateBr(ctx->mergeBB);
                }
                break;
            }
            case 2: {
                /* ── Else body ──────────────────────────────────────── */
                ctx->hasElse = true;
                ctx->elseBB->insertInto(self->currentFunction_);
                self->builder_->SetInsertPoint(ctx->elseBB);
                self->visitCursor(c);
                if (!self->builder_->GetInsertBlock()->getTerminator()) {
                    self->builder_->CreateBr(ctx->mergeBB);
                }
                break;
            }
        }
        ctx->childIdx++;
        return CXChildVisit_Continue;
    }, &ctx);

    /* If there was no else branch, wire up the else block to merge */
    if (!ctx.hasElse) {
        elseBB->insertInto(func);
        builder_->SetInsertPoint(elseBB);
        builder_->CreateBr(mergeBB);
    }

    mergeBB->insertInto(func);
    builder_->SetInsertPoint(mergeBB);

    return nullptr;
}

/* ======================================================================
 *  handleWhileStmt
 *
 *  while (cond) { body }
 *
 *  Generates:
 *            br %while.cond
 *    while.cond: <evaluate cond>
 *            br i1 %cond, %while.body, %while.end
 *    while.body: <body>
 *            br %while.cond
 *    while.end:  <continue>
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleWhileStmt(CXCursor cursor) {
    llvm::Function* func = currentFunction_;

    llvm::BasicBlock* condBB = llvm::BasicBlock::Create(*context_, "while.cond", func);
    llvm::BasicBlock* bodyBB = llvm::BasicBlock::Create(*context_, "while.body");
    llvm::BasicBlock* endBB  = llvm::BasicBlock::Create(*context_, "while.end");

    /* Jump to condition block */
    builder_->CreateBr(condBB);

    struct WhileCtx {
        ClangToIRConverter* self;
        llvm::BasicBlock*   condBB;
        llvm::BasicBlock*   bodyBB;
        llvm::BasicBlock*   endBB;
        int                 childIdx;
    };

    WhileCtx ctx{ this, condBB, bodyBB, endBB, 0 };

    clang_visitChildren(cursor, [](CXCursor c, CXCursor /*parent*/, CXClientData data) {
        auto* ctx = static_cast<WhileCtx*>(data);
        auto* self = ctx->self;

        switch (ctx->childIdx) {
            case 0: {
                /* ── Condition ──────────────────────────────────────── */
                self->builder_->SetInsertPoint(ctx->condBB);
                llvm::Value* cond = self->visitCursor(c);
                cond = self->loadIfAlloca(cond);
                cond = self->builder_->CreateICmpNE(
                    cond,
                    llvm::ConstantInt::get(cond->getType(), 0),
                    "whilecond");
                self->builder_->CreateCondBr(cond, ctx->bodyBB, ctx->endBB);
                break;
            }
            case 1: {
                /* ── Body ───────────────────────────────────────────── */
                ctx->bodyBB->insertInto(self->currentFunction_);
                self->builder_->SetInsertPoint(ctx->bodyBB);
                self->visitCursor(c);
                if (!self->builder_->GetInsertBlock()->getTerminator()) {
                    self->builder_->CreateBr(ctx->condBB);
                }
                break;
            }
        }
        ctx->childIdx++;
        return CXChildVisit_Continue;
    }, &ctx);

    endBB->insertInto(func);
    builder_->SetInsertPoint(endBB);

    return nullptr;
}

/* ======================================================================
 *  handleUnaryOperator
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleUnaryOperator(CXCursor cursor) {
    auto children = visitChildrenOf(cursor);
    if (children.empty() || !children[0]) {
        lastError_ = "Unary operator: no operand";
        return nullptr;
    }

    llvm::Value* operand = loadIfAlloca(children[0]);
    std::string op = getTokenAtCursor(cursor);

    if (op == "-") return builder_->CreateNeg(operand, "negtmp");
    if (op == "!") return builder_->CreateNot(operand, "nottmp");

    lastError_ = "Unsupported unary operator: " + op;
    return nullptr;
}

/* ======================================================================
 *  handleParenExpr — just return the inner expression
 * ====================================================================== */

llvm::Value* ClangToIRConverter::handleParenExpr(CXCursor cursor) {
    auto children = visitChildrenOf(cursor);
    return children.empty() ? nullptr : children[0];
}

/* ======================================================================
 *  Helpers
 * ====================================================================== */

llvm::Type* ClangToIRConverter::getLLVMType(CXType cxType) {
    switch (cxType.kind) {
        case CXType_Int:
        case CXType_Long:
        case CXType_Short:
        case CXType_Char_S:
            return llvm::Type::getInt32Ty(*context_);
        case CXType_Bool:
            return llvm::Type::getInt1Ty(*context_);
        case CXType_Void:
            return llvm::Type::getVoidTy(*context_);
        default:
            /* Default to i32 for unsupported types */
            return llvm::Type::getInt32Ty(*context_);
    }
}

std::string ClangToIRConverter::getCursorSpelling(CXCursor cursor) {
    CXString spelling = clang_getCursorSpelling(cursor);
    std::string result = clang_getCString(spelling);
    clang_disposeString(spelling);
    return result;
}

std::string ClangToIRConverter::getTokenAtCursor(CXCursor cursor) {
    /*
     * For a BinaryOperator or UnaryOperator cursor, we need to identify
     * which operator it represents.  libclang's C API doesn't expose the
     * operator kind directly, so we tokenize the cursor's source range
     * and find the first punctuation token that is a known operator.
     *
     * libclang tokenizes compound operators (<=, >=, ==, !=, &&, ||)
     * as single tokens, so no special reassembly is needed.
     */
    CXSourceRange range = clang_getCursorExtent(cursor);
    CXToken*      tokens = nullptr;
    unsigned      numTokens = 0;
    clang_tokenize(translationUnit_, range, &tokens, &numTokens);

    std::string op;
    for (unsigned i = 0; i < numTokens; i++) {
        if (clang_getTokenKind(tokens[i]) != CXToken_Punctuation)
            continue;

        CXString spelling = clang_getTokenSpelling(translationUnit_, tokens[i]);
        std::string token = clang_getCString(spelling);
        clang_disposeString(spelling);

        /* Known operators */
        if (token == "+"  || token == "-"  || token == "*"  || token == "/"  ||
            token == "%"  || token == "<"  || token == ">"  || token == "<=" ||
            token == ">=" || token == "==" || token == "!=" || token == "&&" ||
            token == "||" || token == "="  || token == "!") {
            op = token;
            break;  /* First operator found is the one we want */
        }
    }
    clang_disposeTokens(translationUnit_, tokens, numTokens);
    return op;
}

llvm::Value* ClangToIRConverter::loadIfAlloca(llvm::Value* val) {
    if (!val) return nullptr;
    if (auto* alloca = llvm::dyn_cast<llvm::AllocaInst>(val)) {
        return builder_->CreateLoad(alloca->getAllocatedType(), alloca, "loadtmp");
    }
    return val;
}

llvm::AllocaInst* ClangToIRConverter::createEntryBlockAlloca(
        llvm::Type* type, const std::string& name) {
    llvm::IRBuilder<> tmpBuilder(
        &currentFunction_->getEntryBlock(),
        currentFunction_->getEntryBlock().begin());
    return tmpBuilder.CreateAlloca(type, nullptr, name);
}
