#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/Casting.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/CallSite.h"

using namespace llvm;

namespace {
    struct SyscallCounter : public llvm::ModulePass {
        static char ID;
        DenseMap<Function*, uint64_t> counts;
        SyscallCounter()
                : ModulePass(ID)
        { }
        bool runOnModule(Module& m) override;
        void print(raw_ostream& out, const Module* m) const override;
        void handleInstruction(CallSite cs);
    };

    bool
    SyscallCounter::runOnModule(Module& m) {
        for (auto& f : m)
            for (auto& bb : f)
                for (auto& i : bb)
                    handleInstruction(CallSite(&i));
        return false; // False because we didn't change the Module
    }

    void
    SyscallCounter::handleInstruction(CallSite cs) {
        // Check whether the instruction is actually a call
        if (!cs.getInstruction()) { return; }
        // Check whether the called function is directly invoked
        auto called = cs.getCalledValue()->stripPointerCasts();
        auto fun = dyn_cast<Function>(called);
        if (!fun) { return; }
        // Update the count for the particular call
        auto count = counts.find(fun);
        if (counts.end() == count) {
            count = counts.insert(std::make_pair(fun, 0)).first;
        }
        ++count->second;
    }
}


char SyscallCounter::ID = 0;

static void registerSyscallPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase &PM) {
    PM.add(new SyscallCounter());
}
static RegisterStandardPasses
        RegisterMyPass(PassManagerBuilder::EP_EarlyAsPossible,
                       registerSyscallPass);
