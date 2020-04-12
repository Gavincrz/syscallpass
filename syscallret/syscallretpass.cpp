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

    const StringSet<> all_syscall = {"read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek",
    "ioctl", "pread", "pwrite", "readv", "writev", "access", "pipe", "select",
    "dup", "dup2", "pause", "nanosleep", "getpid", "sendfile", "socket", "connect",
    "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen",
    "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "uname", "flock", "fsync",
    "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir",
    "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown",
    "lchown", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "getuid", "getgid", "setuid",
    "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid",
    "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "getsid",
    "utime", "mknod", "statfs", "fstatfs", "sysfs", "setpriority", "sched_setparam",
    "sched_setscheduler", "mlock", "munlock", "mlockall", "munlockall", "vhangup",
    "pivot_root", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount",
    "umount2", "swapon", "swapoff", "sethostname", "setdomainname", "iopl",
    "ioperm", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr",
    "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr",
    "flistxattr", "removexattr", "lremovexattr", "fremovexattr",
    "time", "sched_setaffinity", "epoll_create", "getdents", "posix_fadvise",
    "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep",
    "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "mq_unlink", "mq_timedsend",
    "mq_timedreceive", "mq_notify", "mq_getsetattr", "inotify_init", "inotify_add_watch",
    "inotify_rm_watch", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "fstatat",
    "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat",
    "pselect", "ppoll", "splice", "tee", "sync_file_range", "vmsplice", "utimensat",
    "epoll_pwait", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime",
    "accept4", "eventfd", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev",
    "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit", "name_to_handle_at", "open_by_handle_at",
    "clock_adjtime", "syncfs", "sendmmsg", "setns"};

    raw_ostream &outf() {
        // Set buffer settings to model stdout behavior.
        std::error_code EC;
        static raw_fd_ostream S("/home/gavin/llvm_syscallret.txt", EC, sys::fs::CD_OpenAlways, sys::fs::FA_Write,
                                sys::fs::OF_Append);
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
        M.dump();
        // errs() << " running on Module .. " << M.getName() << "\n";
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
//                    i->dump();
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
                if (auto *castI = dyn_cast<CastInst>(i)) {
                    //errs() << "cast opcode: " << castI->getOpcodeName() << "\n";
                    handleUsage(i, syscall, offsetL, offsetR);
                }
                if (opCode == Instruction::ICmp) {
                    ICmpInst *CMPI= dyn_cast<ICmpInst>(i);
//                    CMPI->dump();
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

    void handleStruct(CallSite cs, int index, int ptindex, int offset, StringRef syscallName, StringRef name) {
        Value *arg = cs.getArgument(index);
        const Twine &outName = syscallName + "~" + name;
        SmallString<128> nameStorage;
        StringRef outNameStr = outName.toStringRef(nameStorage);
//
//        selfGEP = dyn_cast<GetElementPtrInst>(arg);
//        if (selfGEG) {
//
//        }

        for (User* user : arg->users()){
            GetElementPtrInst * ptrInst = dyn_cast<GetElementPtrInst>(user);
            if (ptrInst){
                // ptrInst->dump();
                // get the ptindex index
                if (ptindex >=  ptrInst->getNumIndices()) {
                    return;
                }
                User::op_iterator I = ptrInst->idx_begin();
                I += ptindex;
                Value* indexV = I->get();
                // get constant value
                ConstantInt* CI = dyn_cast<ConstantInt>(indexV);
                if (CI && CI->getSExtValue() == offset) {
                    // get the load instruction
                    for (User* ptrUser : ptrInst->users()) {
                        if (LoadInst * loadInst = dyn_cast<LoadInst>(ptrUser)) {
                            errs() << "found syscall: " << outNameStr << "\n";
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
        if (syscallName.equals("__errno_location")) {
            // get previous 5 instructions to try to find syscall
            int retry = 5;
            bool found = false;
            Instruction *prevI = I->getPrevNode();
            StringRef outputName = "errno~unknown";
            while (retry && !found && prevI) {
                CallInst * caI = dyn_cast<CallInst>(prevI);
                if (caI) {
                    Function *fun = caI->getCalledFunction();
                    if (fun) {
                        StringRef found_name = fun->getName();
                        const Twine &retName = "errno~" + found_name;
                        SmallString<128> nameStorage;
                        outputName = retName.toStringRef(nameStorage);
                        break;
                    }
                }
                prevI = prevI->getPrevNode();
                retry--;
            }
            errs() << "found " << outputName << "\n";
            handleUsage(I,outputName , 0, 0);
        }
        /* analyze return value */
        if (!syscallSet.count(syscallName)) {
            return;
        }

        const Twine &retName = syscallName + "~ret_v";
        SmallString<128> nameStorage;
        StringRef retNameStr = retName.toStringRef(nameStorage);
        errs() << "found syscall: " << retName << " " << retNameStr <<"\n";
        handleUsage(I, retNameStr, 0, 0);

        // handle each retbuf separately
        if (syscallName.equals("fstat")) {
            handleStruct(cs, 1, 1, 3, syscallName, "st_mode_v");
        }
        if (syscallName.equals("stat")) {
            handleStruct(cs, 1, 1, 3, syscallName, "st_mode_v");
        }
        if (syscallName.equals("lstat")) {
            handleStruct(cs, 1, 1, 3, syscallName, "st_mode_v");
        }
//        if (syscallName.equals("epoll_wait")) {
//            handleStruct(cs, 1, 2, 0, syscallName, "events_v");
//        }
//        if (syscallName.equals("epoll_wait")) {
//            handleStruct(cs, 1, 2, 1, syscallName, "data_v");
//        }

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

