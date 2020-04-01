#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/CallSite.h"
#include "llvm/Support/FileSystem.h"

using namespace llvm;

namespace {

    raw_ostream &outf() {
        // Set buffer settings to model stdout behavior.
        std::error_code EC;
        static raw_fd_ostream S("/home/gavin/llvm_output.txt", EC, sys::fs::OF_None);
        assert(!EC);
        return S;
    }

    raw_ostream & outf(StringRef filename) {
        // Set buffer settings to model stdout behavior.
        std::error_code EC;
        static raw_fd_ostream S("-", EC, sys::fs::OF_None);
        assert(!EC);
        return S;
    }

    struct SyscallCounter : public llvm::ModulePass {
        static char ID;
        DenseMap<Function*, uint64_t> counts;
        SyscallCounter()
                : ModulePass(ID)
        { }
        bool runOnModule(Module &m) override;
        void print(raw_ostream& out, const Module* m) const override;
        void handleInstruction(CallSite cs);

        StringRef getPassName() const override { return "Syscall Counter";}
    };

    bool
    SyscallCounter::runOnModule(Module &M) {
        outf() << "I am here run on module" << M.getName() << "\n";
        for (auto &F : M) {
            outf() << "I saw a function called " << F.getName() << "!\n";
        }

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
        errs() << "enter handle instruction\n";
//        // Check whether the instruction is actually a call
//        if (!cs.getInstruction()) { return; }
//        // Check whether the called function is directly invoked
//        auto called = cs.getCalledValue()->stripPointerCasts();
//        auto fun = dyn_cast<Function>(called);
//        if (!fun) { return; }
//        // Update the count for the particular call
//        auto count = counts.find(fun);
//        if (counts.end() == count) {
//            count = counts.insert(std::make_pair(fun, 0)).first;
//        }
//        ++count->second;
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

