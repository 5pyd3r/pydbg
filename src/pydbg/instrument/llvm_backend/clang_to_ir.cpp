// pydbg LLVM instrumentation backend
/*
 * =========================================================================
 *  ClangToIRConverter — Implementation (clang C++ AST API, libclang-free)
 * =========================================================================
 *  Parses C source with clang::tooling::runToolOnCodeWithArgs, then walks
 *  the clang AST (clang::Stmt / clang::Expr / clang::Decl) and emits LLVM
 *  IR with IRBuilder. Replaces the old libclang C-API visitor.
 *
 *  Dispatch model:
 *    - emitFunction()   top-level function declaration/definition
 *    - emitStmt()       statement-level dispatch (CompoundStmt, ReturnStmt,
 *                       DeclStmt, IfStmt, WhileStmt, expression stmts)
 *    - emitExpr()       expression-level dispatch via dyn_cast on concrete
 *                       clang::Expr subclasses
 *  Local variables are entry-block allocas (lvalues); every consumer calls
 *  loadIfAlloca() to load, mirroring the old converter's model.
 * =========================================================================
 */

#include "clang_to_ir.h"

#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/SmallVector.h>

#include <clang/AST/ASTContext.h>
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Stmt.h>
#include <clang/AST/Expr.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Tooling/Tooling.h>
#include <clang/Basic/Diagnostic.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

/* ======================================================================
 *  Frontend action + diagnostic capture
 * ====================================================================== */

/*
 * Captures the first Error/Fatal diagnostic into the converter's lastError_
 * as "Parse error: <msg>". Installed as the DiagnosticsEngine client so the
 * message is recorded at emission time (robust even if the frontend action
 * is aborted before EndSourceFileAction).
 */
class ClangToIRErrorConsumer : public clang::DiagnosticConsumer {
public:
    explicit ClangToIRErrorConsumer(ClangToIRConverter* conv) : conv_(conv) {}

    void HandleDiagnostic(clang::DiagnosticsEngine::Level level,
                          const clang::Diagnostic& info) override {
        if (level == clang::DiagnosticsEngine::Error ||
            level == clang::DiagnosticsEngine::Fatal) {
            llvm::SmallVector<char, 256> buf;
            info.FormatDiagnostic(buf);
            conv_->setParseError(std::string(buf.begin(), buf.end()));
        }
        clang::DiagnosticConsumer::HandleDiagnostic(level, info);
    }

private:
    ClangToIRConverter* conv_;
};

/*
 * AST consumer handed to clang by the frontend action. Once the translation
 * unit is ready it asks the converter to emit IR for the whole TU.
 */
class ClangToIRConsumer : public clang::ASTConsumer {
public:
    explicit ClangToIRConsumer(ClangToIRConverter* conv) : conv_(conv) {}

    void HandleTranslationUnit(clang::ASTContext& Ctx) override {
        conv_->convertTranslationUnit(Ctx);
    }

private:
    ClangToIRConverter* conv_;
};

/*
 * ASTFrontendAction: (1) installs the diagnostic capturer before parsing,
 * (2) returns a consumer that drives IR generation on completion.
 */
class ClangToIRFrontendAction : public clang::ASTFrontendAction {
public:
    explicit ClangToIRFrontendAction(ClangToIRConverter* conv) : conv_(conv) {}

    bool BeginSourceFileAction(clang::CompilerInstance& CI) override {
        CI.getDiagnostics().setClient(new ClangToIRErrorConsumer(conv_),
                                      /*ShouldOwnClient=*/true);
        /* Fatal diagnostics must not call the default abort() handler — the
           host process (the Python extension) must survive a bad payload. */
        CI.getDiagnostics().setFatalsAsError(true);
        return true;
    }

    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance& CI, clang::StringRef /*InFile*/) override {
        return std::make_unique<ClangToIRConsumer>(conv_);
    }

private:
    ClangToIRConverter* conv_;
};

/* ======================================================================
 *  Constructor / Destructor
 * ====================================================================== */

ClangToIRConverter::ClangToIRConverter()
    : context_(std::make_unique<llvm::LLVMContext>()),
      builder_(std::make_unique<llvm::IRBuilder<>>(*context_)) {}

ClangToIRConverter::~ClangToIRConverter() = default;

/* ======================================================================
 *  convert() — Top-level entry point
 * ====================================================================== */

std::unique_ptr<llvm::Module> ClangToIRConverter::convert(
        const std::string& cSource,
        const std::string& filename) {
    lastError_.clear();

    /* ── Create a fresh LLVM module ──────────────────────────────────── */
    module_ = std::make_unique<llvm::Module>("jit_module", *context_);

    /* ── Parse C source with the clang C++ frontend ──────────────────── */
    /* Include-free C parses without an explicit -resource-dir (verified by
       spike), matching the old libclang path. */
    std::vector<std::string> args = { "-std=c11", "-fsyntax-only" };
    bool ok = clang::tooling::runToolOnCodeWithArgs(
        std::make_unique<ClangToIRFrontendAction>(this),
        cSource, args, filename);

    if (!lastError_.empty()) {
        return nullptr;   /* parse error captured by ClangToIRErrorConsumer */
    }
    if (!ok) {
        lastError_ = "Failed to parse translation unit";
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
 *  convertTranslationUnit() — top-level decls
 * ====================================================================== */

void ClangToIRConverter::convertTranslationUnit(clang::ASTContext& ctx) {
    clang::TranslationUnitDecl* tu = ctx.getTranslationUnitDecl();
    for (auto it = tu->decls_begin(); it != tu->decls_end(); ++it) {
        if (!lastError_.empty()) return;
        if (auto* fd = llvm::dyn_cast<clang::FunctionDecl>(*it)) {
            emitFunction(fd);
        }
        /* Non-function top-level decls are ignored, matching the old
           TU-level walk (which only produced IR for FunctionDecls). */
    }
}

/* ======================================================================
 *  emitFunction() — prototype (extern) or definition
 * ====================================================================== */

void ClangToIRConverter::emitFunction(clang::FunctionDecl* fd) {
    const std::string name = fd->getNameAsString();

    /* ── Build the LLVM function signature ───────────────────────────── */
    llvm::Type* retType = getLLVMType(fd->getReturnType());
    std::vector<llvm::Type*>  paramTypes;
    std::vector<std::string>  paramNames;
    for (auto* param : fd->parameters()) {
        paramTypes.push_back(getLLVMType(param->getType()));
        paramNames.push_back(param->getNameAsString());
    }
    llvm::FunctionType* ft = llvm::FunctionType::get(retType, paramTypes, false);

    /* ── Declaration only (extern) — create the prototype ────────────── */
    if (!fd->isThisDeclarationADefinition()) {
        if (!module_->getFunction(name)) {
            llvm::Function::Create(ft, llvm::Function::ExternalLinkage,
                                   name, module_.get());
        }
        return;
    }

    /* ── Definition — create/reuse function, emit body ───────────────── */
    llvm::Function* func = module_->getFunction(name);
    if (!func) {
        func = llvm::Function::Create(ft, llvm::Function::ExternalLinkage,
                                      name, module_.get());
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

    /* Emit the function body */
    emitStmt(fd->getBody());

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
}

/* ======================================================================
 *  emitStmt() — statement dispatch
 * ====================================================================== */

void ClangToIRConverter::emitStmt(clang::Stmt* s) {
    if (!s || !lastError_.empty()) return;

    if (auto* comp = llvm::dyn_cast<clang::CompoundStmt>(s)) {
        for (auto* child : comp->body()) emitStmt(child);
        return;
    }
    if (auto* ret = llvm::dyn_cast<clang::ReturnStmt>(s)) {
        emitReturnStmt(ret);
        return;
    }
    if (auto* declStmt = llvm::dyn_cast<clang::DeclStmt>(s)) {
        for (auto* decl : declStmt->decls()) {
            if (auto* vd = llvm::dyn_cast<clang::VarDecl>(decl)) {
                emitVarDecl(vd);
            }
        }
        return;
    }
    if (auto* ifs = llvm::dyn_cast<clang::IfStmt>(s)) {
        emitIfStmt(ifs);
        return;
    }
    if (auto* wh = llvm::dyn_cast<clang::WhileStmt>(s)) {
        emitWhileStmt(wh);
        return;
    }
    if (auto* expr = llvm::dyn_cast<clang::Expr>(s)) {
        emitExpr(expr);   /* expression statement — value discarded */
        return;
    }

    /* Unknown statement — visit children as a fallback */
    for (auto* child : s->children()) emitStmt(child);
}

/* ======================================================================
 *  emitReturnStmt
 * ====================================================================== */

void ClangToIRConverter::emitReturnStmt(clang::ReturnStmt* ret) {
    clang::Expr* val = ret->getRetValue();
    if (!val) {
        builder_->CreateRetVoid();
        return;
    }
    llvm::Value* retVal = coerceToInt(loadIfAlloca(emitExpr(val)));
    if (!retVal) return;
    builder_->CreateRet(retVal);
}

/* ======================================================================
 *  emitIfStmt
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

void ClangToIRConverter::emitIfStmt(clang::IfStmt* ifs) {
    llvm::Function* func = currentFunction_;

    llvm::BasicBlock* thenBB  = llvm::BasicBlock::Create(*context_, "if.then", func);
    llvm::BasicBlock* elseBB  = llvm::BasicBlock::Create(*context_, "if.else");
    llvm::BasicBlock* mergeBB = llvm::BasicBlock::Create(*context_, "if.end");

    llvm::Value* cond = emitExpr(ifs->getCond());
    cond = loadIfAlloca(cond);
    if (!cond) return;   /* condition failed to emit; lastError_ is set */
    cond = builder_->CreateICmpNE(
        cond, llvm::ConstantInt::get(cond->getType(), 0), "ifcond");
    builder_->CreateCondBr(cond, thenBB, elseBB);

    builder_->SetInsertPoint(thenBB);
    emitStmt(ifs->getThen());
    if (!builder_->GetInsertBlock()->getTerminator()) {
        builder_->CreateBr(mergeBB);
    }

    if (clang::Stmt* elseStmt = ifs->getElse()) {
        elseBB->insertInto(func);
        builder_->SetInsertPoint(elseBB);
        emitStmt(elseStmt);
        if (!builder_->GetInsertBlock()->getTerminator()) {
            builder_->CreateBr(mergeBB);
        }
    } else {
        elseBB->insertInto(func);
        builder_->SetInsertPoint(elseBB);
        builder_->CreateBr(mergeBB);
    }

    mergeBB->insertInto(func);
    builder_->SetInsertPoint(mergeBB);
}

/* ======================================================================
 *  emitWhileStmt
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

void ClangToIRConverter::emitWhileStmt(clang::WhileStmt* ws) {
    llvm::Function* func = currentFunction_;

    llvm::BasicBlock* condBB = llvm::BasicBlock::Create(*context_, "while.cond", func);
    llvm::BasicBlock* bodyBB = llvm::BasicBlock::Create(*context_, "while.body");
    llvm::BasicBlock* endBB  = llvm::BasicBlock::Create(*context_, "while.end");

    builder_->CreateBr(condBB);

    builder_->SetInsertPoint(condBB);
    llvm::Value* cond = emitExpr(ws->getCond());
    cond = loadIfAlloca(cond);
    if (!cond) return;   /* condition failed to emit; lastError_ is set */
    cond = builder_->CreateICmpNE(
        cond, llvm::ConstantInt::get(cond->getType(), 0), "whilecond");
    builder_->CreateCondBr(cond, bodyBB, endBB);

    bodyBB->insertInto(func);
    builder_->SetInsertPoint(bodyBB);
    emitStmt(ws->getBody());
    if (!builder_->GetInsertBlock()->getTerminator()) {
        builder_->CreateBr(condBB);
    }

    endBB->insertInto(func);
    builder_->SetInsertPoint(endBB);
}

/* ======================================================================
 *  emitVarDecl — local variable with optional initializer
 * ====================================================================== */

void ClangToIRConverter::emitVarDecl(clang::VarDecl* vd) {
    const std::string name = vd->getNameAsString();
    llvm::Type* type = getLLVMType(vd->getType());

    llvm::AllocaInst* alloca = createEntryBlockAlloca(type, name);
    locals_[name] = alloca;

    if (clang::Expr* init = vd->getInit()) {
        llvm::Value* initVal = coerceToInt(loadIfAlloca(emitExpr(init)));
        if (initVal) {
            builder_->CreateStore(initVal, alloca);
        }
    }
}

/* ======================================================================
 *  emitExpr() — expression dispatch
 * ====================================================================== */

llvm::Value* ClangToIRConverter::emitExpr(clang::Expr* e) {
    if (!e || !lastError_.empty()) return nullptr;

    if (auto* bin = llvm::dyn_cast<clang::BinaryOperator>(e)) {
        return emitBinaryOperator(bin);
    }
    if (auto* call = llvm::dyn_cast<clang::CallExpr>(e)) {
        return emitCallExpr(call);
    }
    if (auto* lit = llvm::dyn_cast<clang::IntegerLiteral>(e)) {
        return emitIntegerLiteral(lit);
    }
    if (auto* ref = llvm::dyn_cast<clang::DeclRefExpr>(e)) {
        return emitDeclRefExpr(ref);
    }
    if (auto* un = llvm::dyn_cast<clang::UnaryOperator>(e)) {
        return emitUnaryOperator(un);
    }
    if (auto* paren = llvm::dyn_cast<clang::ParenExpr>(e)) {
        return emitExpr(paren->getSubExpr());
    }
    if (auto* cast = llvm::dyn_cast<clang::ImplicitCastExpr>(e)) {
        /* C wraps operands in implicit casts (LValueToRValue, integral→bool,
           function-to-pointer decay, …). Unwrap and emit the inner expr. */
        return emitExpr(cast->getSubExpr());
    }

    /* Unknown expression — visit children as a fallback, return last value.
       If no value could be produced (e.g. StringLiteral, InitListExpr with no
       Expr children) report an error rather than silently returning nullptr
       to a consumer that would feed it to IRBuilder. */
    llvm::Value* last = nullptr;
    for (auto* child : e->children()) {
        if (auto* childExpr = llvm::dyn_cast_or_null<clang::Expr>(child)) {
            last = emitExpr(childExpr);
        }
    }
    if (!last && lastError_.empty()) {
        lastError_ = "Unsupported expression node in C subset";
    }
    return last;
}

/* ======================================================================
 *  emitBinaryOperator
 * ====================================================================== */

llvm::Value* ClangToIRConverter::emitBinaryOperator(clang::BinaryOperator* bin) {
    llvm::Value* lhs = emitExpr(bin->getLHS());
    llvm::Value* rhs = emitExpr(bin->getRHS());
    if (!lhs || !rhs) {
        lastError_ = "Binary operator: expected 2 operands";
        return nullptr;
    }

    switch (bin->getOpcode()) {
        /* ── Assignment ──────────────────────────────────────────────── */
        case clang::BO_Assign: {
            rhs = loadIfAlloca(rhs);
            builder_->CreateStore(rhs, lhs);
            return rhs;
        }

        /* ── Arithmetic ──────────────────────────────────────────────── */
        case clang::BO_Add: return builder_->CreateAdd(loadIfAlloca(lhs), loadIfAlloca(rhs), "addtmp");
        case clang::BO_Sub: return builder_->CreateSub(loadIfAlloca(lhs), loadIfAlloca(rhs), "subtmp");
        case clang::BO_Mul: return builder_->CreateMul(loadIfAlloca(lhs), loadIfAlloca(rhs), "multmp");
        case clang::BO_Div: return builder_->CreateSDiv(loadIfAlloca(lhs), loadIfAlloca(rhs), "divtmp");
        case clang::BO_Rem: return builder_->CreateSRem(loadIfAlloca(lhs), loadIfAlloca(rhs), "remtmp");

        /* ── Comparison ──────────────────────────────────────────────── */
        case clang::BO_LT: return builder_->CreateICmpSLT(loadIfAlloca(lhs), loadIfAlloca(rhs), "cmptmp");
        case clang::BO_GT: return builder_->CreateICmpSGT(loadIfAlloca(lhs), loadIfAlloca(rhs), "cmptmp");
        case clang::BO_LE: return builder_->CreateICmpSLE(loadIfAlloca(lhs), loadIfAlloca(rhs), "cmptmp");
        case clang::BO_GE: return builder_->CreateICmpSGE(loadIfAlloca(lhs), loadIfAlloca(rhs), "cmptmp");
        case clang::BO_EQ: return builder_->CreateICmpEQ(loadIfAlloca(lhs), loadIfAlloca(rhs), "cmptmp");
        case clang::BO_NE: return builder_->CreateICmpNE(loadIfAlloca(lhs), loadIfAlloca(rhs), "cmptmp");

        /* ── Logical (correct 0/1 result; no short-circuit) ──────────── */
        case clang::BO_LAnd:
        case clang::BO_LOr: {
            lhs = loadIfAlloca(lhs);
            rhs = loadIfAlloca(rhs);
            llvm::Value* zero = llvm::ConstantInt::get(lhs->getType(), 0);
            llvm::Value* l = builder_->CreateICmpNE(lhs, zero, "logl");
            llvm::Value* r = builder_->CreateICmpNE(rhs, zero, "logr");
            llvm::Value* comb = (bin->getOpcode() == clang::BO_LAnd)
                ? builder_->CreateAnd(l, r, "andtmp")
                : builder_->CreateOr(l, r, "ortmp");
            return builder_->CreateZExt(comb, lhs->getType(), "logtmp");
        }

        default:
            lastError_ = "Unsupported binary operator";
            return nullptr;
    }
}

/* ======================================================================
 *  emitCallExpr
 * ====================================================================== */

llvm::Value* ClangToIRConverter::emitCallExpr(clang::CallExpr* call) {
    llvm::Value* callee = emitExpr(call->getCallee());
    llvm::Function* func = llvm::dyn_cast_or_null<llvm::Function>(callee);
    if (!func) {
        lastError_ = "CallExpr: callee is not a function";
        return nullptr;
    }

    std::vector<llvm::Value*> args;
    for (unsigned i = 0; i < call->getNumArgs(); i++) {
        llvm::Value* arg = coerceToInt(loadIfAlloca(emitExpr(call->getArg(i))));
        if (!arg) {
            if (lastError_.empty())
                lastError_ = "CallExpr: argument could not be emitted";
            return nullptr;
        }
        args.push_back(arg);
    }

    if (func->arg_size() != args.size()) {
        lastError_ = "CallExpr: argument count mismatch for " +
                     func->getName().str();
        return nullptr;
    }

    if (func->getReturnType()->isVoidTy()) {
        return builder_->CreateCall(func, args);
    }
    return builder_->CreateCall(func, args, "calltmp");
}

/* ======================================================================
 *  emitIntegerLiteral
 * ====================================================================== */

llvm::Value* ClangToIRConverter::emitIntegerLiteral(clang::IntegerLiteral* lit) {
    return llvm::ConstantInt::get(*context_, lit->getValue());
}

/* ======================================================================
 *  emitDeclRefExpr — reference to a variable or function
 * ====================================================================== */

llvm::Value* ClangToIRConverter::emitDeclRefExpr(clang::DeclRefExpr* ref) {
    std::string name = ref->getNameInfo().getName().getAsString();

    /* Referenced function */
    if (llvm::dyn_cast<clang::FunctionDecl>(ref->getDecl())) {
        llvm::Function* func = module_->getFunction(name);
        if (func) return func;
    }

    /* Local variable (lvalue → alloca) */
    auto it = locals_.find(name);
    if (it != locals_.end()) {
        return it->second;
    }

    /* Functions as a fallback */
    llvm::Function* func = module_->getFunction(name);
    if (func) return func;

    lastError_ = "Unknown identifier: " + name;
    return nullptr;
}

/* ======================================================================
 *  emitUnaryOperator
 * ====================================================================== */

llvm::Value* ClangToIRConverter::emitUnaryOperator(clang::UnaryOperator* un) {
    llvm::Value* operand = loadIfAlloca(emitExpr(un->getSubExpr()));
    if (!operand) {
        lastError_ = "Unary operator: no operand";
        return nullptr;
    }

    switch (un->getOpcode()) {
        case clang::UO_Minus:
            return builder_->CreateNeg(operand, "negtmp");
        case clang::UO_LNot: {
            /* Logical not → 0/1 in the operand's type */
            llvm::Value* zero = llvm::ConstantInt::get(operand->getType(), 0);
            llvm::Value* eq = builder_->CreateICmpEQ(operand, zero, "notcmp");
            return builder_->CreateZExt(eq, operand->getType(), "nottmp");
        }
        default:
            lastError_ = "Unsupported unary operator";
            return nullptr;
    }
}

/* ======================================================================
 *  Helpers
 * ====================================================================== */

llvm::Type* ClangToIRConverter::getLLVMType(clang::QualType qt) {
    if (qt.isNull()) return llvm::Type::getInt32Ty(*context_);
    if (qt->isBooleanType())  return llvm::Type::getInt1Ty(*context_);
    if (qt->isVoidType())     return llvm::Type::getVoidTy(*context_);
    if (qt->isIntegerType())  return llvm::Type::getInt32Ty(*context_);
    /* Default to i32 for unsupported types */
    return llvm::Type::getInt32Ty(*context_);
}

llvm::Value* ClangToIRConverter::coerceToInt(llvm::Value* val) {
    if (!val) return nullptr;
    /* i1 (comparisons, logical ops, _Bool) → i32. i64/i8 never arise in the
       supported C subset, so widening to i32 is always the right coercion. */
    if (val->getType()->isIntegerTy() && !val->getType()->isIntegerTy(32)) {
        return builder_->CreateZExt(val, builder_->getInt32Ty(), "coerce");
    }
    return val;
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
