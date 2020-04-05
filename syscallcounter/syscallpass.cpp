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

using namespace std;
using namespace llvm;

//static cl::opt<string> OutputFilename("sccoutput",
//        cl::desc("Specify output filename for syscall counter"), cl::value_desc("filename"));


namespace {

    raw_ostream &outf() {
        // Set buffer settings to model stdout behavior.
        std::error_code EC;
        static raw_fd_ostream S("/home/gavin/llvm_output.txt", EC, sys::fs::CD_OpenAlways, sys::fs::FA_Write,
                                sys::fs::OF_Append);
        assert(!EC);
        return S;
    }


    struct SyscallCounter : public llvm::ModulePass {
        static char ID;
        DenseMap<Function*, uint64_t> counts;
        SyscallCounter()
                : ModulePass(ID)
        {
            // errs() << "pass initialize" << "\n";
        }
        bool runOnModule(Module &m) override;
        void print(raw_ostream& out, const Module* m) const override;
        void handleInstruction(CallSite cs);
        StringRef outputFile;
        StringRef getPassName() const override { return "Syscall Counter";}
    };

    bool
    SyscallCounter::runOnModule(Module &M) {
        // errs() << " running.. \n";
        outf() << "Module: " << M.getName() << "\n";
        for (auto &F : M) {
            outf() << "Function: " << F.getName() << "\n";
            for (auto &B : F)
                for (auto &I : B)
                    handleInstruction(CallSite(&I));
            outf() << "Function end\n";
        }
        outf() << "Module end\n";
        return false; // False because we didn't change the Module
    }


    void
    SyscallCounter::print(raw_ostream& out, const Module* m) const {
        out << "Function Counts\n"
            << "===============\n";
        for (auto& kvPair : counts) {
            auto* function = kvPair.first;
            uint64_t count = kvPair.second;
            out << function->getName() << " : " << count << "\n";
        }
    }

    void
    SyscallCounter::handleInstruction(CallSite cs) {
        // errs() << "enter handle instruction\n";
        // Check whether the instruction is actually a call
        if (!cs.getInstruction()) { return; }
        // Check whether the called function is directly invoked
        auto called = cs.getCalledValue()->stripPointerCasts();
        auto fun = dyn_cast<Function>(called);
        if (!fun) { return; }
        outf() << fun->getName() << "\n";
    }
}


char SyscallCounter::ID = 0;

static void registerSyscallPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase &PM) {
    PM.add(new SyscallCounter());
}

static RegisterStandardPasses
        RegisterMyPass(PassManagerBuilder::EP_ModuleOptimizerEarly, registerSyscallPass);

static RegisterStandardPasses
        RegisterMyPass0(PassManagerBuilder::EP_EnabledOnOptLevel0, registerSyscallPass);

