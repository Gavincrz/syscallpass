#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
using namespace llvm;

namespace {
    struct SkeletonPass : public ModulePass {
        static char ID;
        DenseMap<Function*, uint64_t> counts;
        SkeletonPass() : ModulePass(ID) {}

        virtual bool runOnModule(Module &F) {
            for (auto& f : m)
                for (auto& bb : f)
                    for (auto& i : bb)
                        handleInstruction(CallSite(&i));
            return false; // False because we didn't change the Module
        }

    };
}

char SkeletonPass::ID = 0;

// Automatically enable the pass.
// http://adriansampson.net/blog/clangpass.html
static void registerSkeletonPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase &PM) {
    PM.add(new SkeletonPass());
}
static RegisterStandardPasses
        RegisterMyPass(PassManagerBuilder::EP_EarlyAsPossible,
                       registerSkeletonPass);