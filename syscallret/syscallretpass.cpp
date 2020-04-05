#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/CallSite.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/DerivedUser.h"
#include "llvm/Analysis/MemorySSA.h"

using namespace std;
using namespace llvm;

//static cl::opt<string> OutputFilename("sccoutput",
//        cl::desc("Specify output filename for syscall counter"), cl::value_desc("filename"));


namespace {

    const StringSet<> syscallSet = {
            "read", "open", "openat", "lstat", "write",
            "close", "stat", "fstat", "lstat", "getpid",
            "lseek", "epoll_wait", "dup2", "dup3"
    };

    raw_ostream &outf() {
        // Set buffer settings to model stdout behavior.
        std::error_code EC;
        static raw_fd_ostream S("/home/gavin/llvm_syscallret.txt", EC, sys::fs::OF_None);
        assert(!EC);
        return S;
    }

    struct SyscallRetPass : public llvm::ModulePass {
        static char ID;
        DenseMap<Function*, uint64_t> counts;
        SyscallRetPass()
                : ModulePass(ID)
        {
        }
        bool runOnModule(Module &m) override;
        void handleInstruction(CallSite cs);
        StringRef outputFile;
        StringRef getPassName() const override { return "Syscall Ret Pass";}
    };

    bool
    SyscallRetPass::runOnModule(Module &M) {
        errs() << " running on Module .. " << M.getName() << "\n";
        for (auto &F : M) {
            for (auto &B : F)
                for (auto &I : B) {
                    handleInstruction(CallSite(&I));
                }

        }
        return false; // False because we didn't change the Module
    }

    ConstantInt* getConstant(Value * v) {
        ConstantInt* CI = dyn_cast<ConstantInt>(v);
        if (CI) return CI;
        Instruction *I = dyn_cast<Instruction>(v);
        if (!I) return nullptr;
        switch (I->getOpcode()){
            case Instruction::Load:
            {
                Value *loadV = cast<LoadInst>(I)->getPointerOperand();
                for (User* user : loadV->users()) {
                    Instruction *II = dyn_cast<Instruction>(user);
                    if (!II) continue;
                    unsigned opCode = II->getOpcode();
                    if (opCode == Instruction::Store) {
                        StoreInst *SI = cast<StoreInst>(II);
                        if (SI && SI->getOperand(1) == loadV) {
                            CI = getConstant(SI->getOperand(0));
                        }
                    }
                }
                return CI;
                break;
            }
            default: return nullptr;
        }
    }

    void handleUsage(Value * I, StringRef syscall, int offsetL, int offsetR) {
        for (User* user : I->users())
            if (auto* i = dyn_cast<Instruction>(user)) {
                unsigned opCode = i->getOpcode();
                if (opCode == Instruction::Store) {
                    StoreInst *SI = cast<StoreInst>(i);
                    Value *dst = SI->getOperand(1);
                    if (dst == I) {
                        return;
                    }
                    handleUsage(dst, syscall, offsetL, offsetR);
                }
                if (opCode == Instruction::Load) {
                    handleUsage(i, syscall, offsetL, offsetR);
                }
                if (opCode == Instruction::Add) {
                    auto *addInst = dyn_cast<BinaryOperator>(i);
                    // errs() << "add instruction: \n ";
                    Value *opPtr;
                    Value *op0 = addInst->getOperand(0);
                    Value *op1 = addInst->getOperand(1);
                    if (op0 == I) {
                        opPtr = op1;
                    }
                    else if (op1 == I){
                        opPtr = op0;
                    }
                    else {
                        errs() << "how could this happen? \n";
                        return;
                    }
                    ConstantInt* CI = getConstant(opPtr);
                    if (!CI) {
                        return;
                    }
                    else {
                        int offset = CI->getSExtValue();
                        // errs() << "offset add " << offset << "\n";
                        handleUsage(i, syscall, offsetL + offset, offsetR);
                    }
                }
                if (opCode == Instruction::Sub) {
                    auto *subInst = dyn_cast<BinaryOperator>(i);
                    // errs() << "Sub instruction: \n ";
                    // TODO: handle sub
                }
                if (opCode == Instruction::And) {
                    handleUsage(i, syscall, offsetL, offsetR);
                }
                if (opCode == Instruction::ICmp) {
                    ICmpInst *CMPI= dyn_cast<ICmpInst>(i);
//                    errs() << "comp instruction found for syscall " << syscall
//                        << " offsetL: " << offsetL << " offsetR: " << offsetR << "\n";
                    CmpInst::Predicate pred = CMPI->getPredicate();
                    Value *op0 = CMPI->getOperand(0);
                    Value *op1 = CMPI->getOperand(1);
                    Value *opPtr;
                    bool isLeft;
                    if (op0 == I) {
                        opPtr = op1;
                        isLeft = true;
                    }
                    else if (op1 == I){
                        opPtr = op0;
                        isLeft = false;
                    }
                    else {
                        errs() << "how could this happen? \n";
                        return;
                    }
                    ConstantInt* CI = getConstant(opPtr);
                    if (!CI) {
                        return;
                    }
                    int target = CI->getSExtValue() - offsetL;
                    switch (pred) {
                        case CmpInst::ICMP_EQ:
                        case CmpInst::ICMP_NE:
                            outf() << syscall << " == " << target << "\n";
                            break;
                        case CmpInst::ICMP_UGT:
                        case CmpInst::ICMP_SGT:
                            if (isLeft) {
                                outf() << syscall << " > " << target << "\n";
                            }
                            else {
                                outf() << syscall << " < " << target << "\n";
                            }
                            break;
                        case CmpInst::ICMP_UGE:
                        case CmpInst::ICMP_SGE:
                            if (isLeft) {
                                outf() << syscall << " >= " << target << "\n";
                            }
                            else {
                                outf() << syscall << " <= " << target << "\n";
                            }
                            break;
                        case CmpInst::ICMP_ULT:
                        case CmpInst::ICMP_SLT:
                            if (isLeft) {
                                outf() << syscall << " < " << target << "\n";
                            }
                            else {
                                outf() << syscall << " > " << target << "\n";
                            }
                            break;
                        case CmpInst::ICMP_ULE:
                        case CmpInst::ICMP_SLE:
                            if (isLeft) {
                                outf() << syscall << " <= " << target << "\n";
                            }
                            else {
                                outf() << syscall << " >= " << target << "\n";
                            }
                            break;
                        default:
                            break;
                    }
                }
            }
    }

    void handleStruct(CallSite cs, int index, int offset, StringRef syscallName, StringRef name) {
        Value *arg = cs.getArgument(index);
        Twine outName = Twine(syscallName + "~" + name);
        StringRef outNameStr = outName.str();

        for (User* user : arg->users()){
            GetElementPtrInst * ptrInst = dyn_cast<GetElementPtrInst>(user);
            if (ptrInst){
                ptrInst->dump();
                // get the second index
                User::op_iterator I = ptrInst->idx_begin();
                ++I;
                Value* indexV = I->get();
                // get constant value
                ConstantInt* CI = dyn_cast<ConstantInt>(indexV);
                if (CI && CI->getSExtValue() == offset) {
                    // get the load instruction
                    for (User* ptrUser : ptrInst->users()) {
                        if (LoadInst * loadInst = dyn_cast<LoadInst>(ptrUser)) {
                            handleUsage(loadInst, outNameStr, 0, 0);
                        }
                    }
                }
            }

        }
    }

    void
    SyscallRetPass::handleInstruction(CallSite cs) {

        Instruction *I = cs.getInstruction();
        if (!I) {
            return;
        }
        Function *fun = cs.getCalledFunction();
        if (!fun) {
            return;
        }
        StringRef syscallName = fun->getName();
        /* analyze return value */
        if (!syscallSet.count(syscallName)) {
            return;
        }
        Twine retName = Twine(syscallName + "~" + "ret_v");
        StringRef retNameStr = retName.str();
        handleUsage(I, retNameStr, 0, 0);

        // handle each retbuf separately
        if (syscallName.equals("fstat")) {
            handleStruct(cs, 1, 3, syscallName, "st_mode_v");
//            handleStruct(cs, 1, 3, syscallName, "st_mode_v");
        }
    }
}


char SyscallRetPass::ID = 0;

static void registerSyscallRetPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase &PM) {
    PM.add(new SyscallRetPass());
}

static RegisterStandardPasses
        RegisterMyPass(PassManagerBuilder::EP_ModuleOptimizerEarly, registerSyscallRetPass);

static RegisterStandardPasses
        RegisterMyPass0(PassManagerBuilder::EP_EnabledOnOptLevel0, registerSyscallRetPass);

