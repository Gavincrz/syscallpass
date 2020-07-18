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
            "read", "open", "openat", "lstat64", "stat64", "fstat64", "write",
            "close", "stat", "fstat", "lstat", "getpid",
            "lseek", "epoll_wait", "dup2", "dup3", "epoll_create", "poll", "socket",
            "setsockopt", "listen", "epoll_ctl", "setgroups", "getuid", "access", "getgid",
            "setuid", "setgid", "connect", "prlimit", "getsockopt", "accept", "accept4",
            "sendfile", "getcwd", "writev", "setsid", "sendto", "chroot", "getdents", "getppid", "dup",
            "nanosleep", "getsockname", "pipe", "clock_gettime", "select", "geteuid", "getegid", "uname",
            "recvmsg", "getpgrp", "setresuid", "getpeername", "setresgid", "getgroups", "chdir", "socketpair",
            "poll", "sysinfo", "readlink", "link", "chmod", "mkdir", "unlink", "rename", "pread", "pread64",
            "symlink", "setitimer", "statfs", "wait4", "sendmsg", "epoll_create1", "recvfrom"
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
        errs() << " running on Module .. " << M.getName() << "\n";
        M.dump();
        for (auto &F : M) {
            for (auto &B : F)
                for (auto &I : B) {
                    handleInstruction(CallSite(&I));
                }

        }
        return false; // False because we didn't change the Module
    }


    Value* getConstant(Value * v) {
        Value * retv;
        ConstantInt* CI = dyn_cast<ConstantInt>(v);
        if (CI) return CI;
        ConstantPointerNull* PN = dyn_cast<ConstantPointerNull>(v);
        if (PN) return PN;
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
                            retv = getConstant(SI->getOperand(0));
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
                else if (opCode == Instruction::Load) {
                    handleUsage(i, syscall, offsetL, offsetR);
                }
                else if (opCode == Instruction::Add) {
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

                    int offset = 0;
                    Value* retv = getConstant(opPtr);
                    ConstantInt* CI = dyn_cast<ConstantInt>(opPtr);
                    if (CI) {
                        offset = CI->getSExtValue();
                    }
                    else {
                        ConstantPointerNull* PN = dyn_cast<ConstantPointerNull>(opPtr);
                        if (PN) {
                            offset = 0;
                        }
                        else {
                            return;
                        }
                    }
                    // errs() << "offset add " << offset << "\n";
                    handleUsage(i, syscall, offsetL + offset, offsetR);

                }
                else if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(i)) {
                    handleUsage(i, syscall, offsetL, offsetR);
                }
                else if (opCode == Instruction::Sub) {
                    auto *subInst = dyn_cast<BinaryOperator>(i);
                    // errs() << "Sub instruction: \n ";
                    // TODO: handle sub
                }
                else if (opCode == Instruction::And) {
                    handleUsage(i, syscall, offsetL, offsetR);
                }
                else if (auto *castI = dyn_cast<CastInst>(i)) {
                    //errs() << "cast opcode: " << castI->getOpcodeName() << "\n";
                    handleUsage(i, syscall, offsetL, offsetR);
                }
                else if (SwitchInst *SwI = dyn_cast<SwitchInst>(i)) {
                    // handle swith Instruction
                    // check if condition is self
//                    errs() << "switch statement found\n";
//                    SwI->dump();
//                    SwI->getCondition()->dump();
//                    I->dump();
                    if (SwI->getCondition() == I) {
//                        errs() << "condition is self\n";
                        // iterate through all the cases
                        for (SwitchInst::CaseIt it = SwI->case_begin(), e = SwI->case_end();
                             it != e; ++it) {
                            // get value of each case
                            ConstantInt * CI = it->getCaseValue();
                            int target = CI->getSExtValue() - offsetL;
                            outf() << syscall << " == " << target << "\n";
                        }
                    }
                }
                else if (opCode == Instruction::ICmp) {
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

                    int target = 0;
                    Value* retv = getConstant(opPtr);
                    ConstantInt* CI = dyn_cast<ConstantInt>(opPtr);
                    if (CI) {
                        target = CI->getSExtValue() - offsetL;
                    }
                    else {
                        ConstantPointerNull* PN = dyn_cast<ConstantPointerNull>(opPtr);
                        if (PN) {
                            target = 0 - offsetL;
                        }
                        else {
                            return;
                        }
                    }

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

    void handle_arg_GEP(Value *arg, int ptindex, int offset, StringRef outNameStr) {
        for (User* user : arg->users()){
            GetElementPtrInst * ptrInst = dyn_cast<GetElementPtrInst>(user);
            if (ptrInst){
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
                        handleUsage(ptrUser, outNameStr, 0, 0);
//                        if (LoadInst * loadInst = dyn_cast<LoadInst>(ptrUser)) {
//                            errs() << "found syscall: " << outNameStr << "\n";
//                            handleUsage(loadInst, outNameStr, 0, 0);
//                        }
                    }
                }
            }
        }
    }

    void handleArgument(CallSite cs, int index, StringRef syscallName, StringRef name) {
        Value *arg = cs.getArgument(index);
        const Twine &outName = syscallName + "~" + name;
        SmallString<128> nameStorage;
        StringRef outNameStr = outName.toStringRef(nameStorage);
        // check if it self is a cast instruction, if so, turn it back to the origin

        if (auto *castI = dyn_cast<CastInst>(arg)) {
            Value *origin =  castI->getOperand(0);
            origin->dump();
            // find comparison on the origin
            handleUsage(origin, outNameStr, 0, 0);
        }
        else {
            handleUsage(arg, outNameStr, 0, 0);
        }
    }

    void handleStruct(CallSite cs, int index, int ptindex, int offset, StringRef syscallName, StringRef name) {
        Value *arg = cs.getArgument(index);
        const Twine &outName = syscallName + "~" + name;
        SmallString<128> nameStorage;
        StringRef outNameStr = outName.toStringRef(nameStorage);
//
        GetElementPtrInst *selfGEP = dyn_cast<GetElementPtrInst>(arg);
        if (selfGEP) {
//            selfGEP->dump();
            Value * operand = selfGEP->getPointerOperand();
            if (operand) {
//                operand->dump();
                for (User* operand : operand->users()) {
                    // find arrayidx
//                    operand->dump();
                    GetElementPtrInst * operandUser = dyn_cast<GetElementPtrInst>(operand);
                    if (operandUser && operandUser != arg){
                        handle_arg_GEP(operandUser, ptindex, offset, outNameStr);
                    }
                }
            }
        }
        else {
            handle_arg_GEP(arg, ptindex, offset, outNameStr);
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
        if (syscallName.equals("fstat") || syscallName.equals("stat") || syscallName.equals("lstat")) {
            handleStruct(cs, 1, 1, 0, syscallName, "st_dev_v");
            handleStruct(cs, 1, 1, 1, syscallName, "st_ino_v");
            handleStruct(cs, 1, 1, 2, syscallName, "st_nlink_v");
            handleStruct(cs, 1, 1, 3, syscallName, "st_mode_v");
            handleStruct(cs, 1, 1, 4, syscallName, "st_uid_v");
            handleStruct(cs, 1, 1, 5, syscallName, "st_gid_v");
            handleStruct(cs, 1, 1, 8, syscallName, "st_size_v");
            handleStruct(cs, 1, 1, 9, syscallName, "st_blksize_v");
            handleStruct(cs, 1, 1, 10, syscallName, "st_block_v");
        }
        else if (syscallName.equals("epoll_wait")) {
            handleStruct(cs, 1, 1, 0, syscallName, "events_v");
        }
        else if (syscallName.equals("epoll_wait")) {
            handleStruct(cs, 1, 1, 1, syscallName, "data_v");
        }
//        if (syscallName.equals("poll")) {
//            handleStruct(cs, 0, 1, 2, syscallName, "revents_v");
//        }
//        if (syscallName.equals("poll")) {
//            handleStruct(cs, 0, 1, 0, syscallName, "fd_v");
//        }
        else if (syscallName.equals("prlimit")) {
            handleStruct(cs, 3, 1, 0, syscallName, "rlim_cur_v");
            handleStruct(cs, 3, 1, 1, syscallName, "rlim_max_v");
        }
        else if (syscallName.equals("getsockopt")) {
            handleArgument(cs, 3, syscallName, "optval_v");
            handleArgument(cs, 4, syscallName, "optlen_v");
        }
        else if (syscallName.equals("accept4")
        || syscallName.equals("accept")
        || syscallName.equals("getsockname")
        || syscallName.equals("getpeername")) {
            handleArgument(cs, 1, syscallName, "addr_v");
            handleArgument(cs, 2, syscallName, "addrlen_v");
        }
        else if (syscallName.equals("sendfile")) {
            handleArgument(cs, 2, syscallName, "offset_v");
        }
        else if (syscallName.equals("wait4")) {
            handleArgument(cs, 1, syscallName, "wstatus_v");
        }
        else if (syscallName.equals("recvfrom")) {
            handleArgument(cs, 4, syscallName, "addr_v");
            handleArgument(cs, 5, syscallName, "addrlen_v");
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

