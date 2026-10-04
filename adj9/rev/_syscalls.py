#!/usr/bin/env python3
import sys, collections
sys.path.insert(0,'.')
from _fold_exact import data, secs
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
for nm,(a,o,s) in secs.items():
    if nm=='.text': TA,TO,TS=a,o,s; break
insns=list(md.disasm(data[TO:TO+TS],TA))
idx={i.address:n for n,i in enumerate(insns)}
SYSCALL_PLT=0x148b30
callers=[i.address for i in insns if i.mnemonic=='bl' and i.operands and i.operands[0].type==2 and i.operands[0].imm==SYSCALL_PLT]
print("syscall bl call sites:",len(callers))
# arm64 syscall numbers
NR={56:'openat',278:'getrandom',63:'read',64:'write',57:'close',160:'uname',
    172:'getpid',169:'gettimeofday',113:'clock_gettime',96:'set_tid_address',
    178:'rt_sigaction',261:'prlimit64',129:'kill',117:'ptrace',215:'munmap',
    222:'mmap',98:'futex',48:'faccessat',79:'newfstatat',214:'brk',61:'getdents64',
    168:'getcpu',167:'prctl',260:'wait4',220:'clone',221:'execve',29:'ioctl',
    62:'lseek',46:'ftruncate',93:'exit',94:'exit_group',101:'nanosleep',
    35:'nanosleep_old',131:'tgkill',134:'rt_sigprocmask',135:'rt_sigpending',
    199:'getuid',200:'getgid',174:'getuid32',198:'socket',203:'connect',
    206:'sendto',207:'recvfrom',211:'sendmsg',212:'recvmsg',66:'writev',
    65:'readv',276:'renameat2',38:'renameat',34:'mkdirat',53:'fchmodat',
    267:'sync_file_range',291:'statx',59:'pipe2',277:'seccomp',281:'socketpair',
    175:'geteuid',176:'getegid',79:'newfstatat',80:'fstat',128:'rt_sigtimedwait'}
def nr_of(addr):
    # scan backwards for mov w0/x0,#imm with no intervening bl
    i=idx[addr]-1; seen=0
    while i>=0 and seen<40:
        ins=insns[i]
        if ins.mnemonic=='bl': break
        if ins.mnemonic in ('mov','movz','movk') and ins.op_str.startswith(('w0,','x0,')):
            s=ins.op_str.split('#')[-1]
            try: return int(s,16)
            except: return None
        i-=1; seen+=1
    return None
print()
print("addr      nr(dec) name")
for c in sorted(callers):
    n=nr_of(c)
    nm=NR.get(n,'?') if n is not None else '?'
    print("0x%06x  %-6s %s"%(c, n if n is not None else '?', nm))
