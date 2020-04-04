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
            errs() << "pass initialize" << "\n";
        }
        bool runOnModule(Module &m) override;
        void print(raw_ostream& out, const Module* m) const override;
        void handleInstruction(CallSite cs);
        StringRef outputFile;
        StringRef getPassName() const override { return "Syscall Counter";}
    };

    bool
    SyscallRetPass::runOnModule(Module &M) {
        errs() << " running.. \n";
        for (auto &F : M) {
            for (auto &B : F)
                for (auto &I : B)
                    handleInstruction(CallSite(&I));
        }
        return false; // False because we didn't change the Module
    }


    void
    SyscallRetPass::print(raw_ostream& out, const Module* m) const {
        out << "Function Counts\n"
            << "===============\n";
        for (auto& kvPair : counts) {
            auto* function = kvPair.first;
            uint64_t count = kvPair.second;
            out << function->getName() << " : " << count << "\n";
        }
    }
    bool
    isSyscall(StringRef ) {

    }

    void
    SyscallRetPass::handleInstruction(CallSite cs) {
        // Check whether the instruction is actually a call
        if (!cs.getInstruction()) { return; }
        // Check whether the called function is directly invoked
        auto called = cs.getCalledValue()->stripPointerCasts();
        auto fun = dyn_cast<Function>(called);
        if (!fun) { return; }
        StringRef funcName = fun->getName();
        if (syscallSet.count(funcName)) {
            errs() << "found syscall instruction\n";
            cs.dump();
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

