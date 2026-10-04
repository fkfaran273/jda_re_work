import sys,re,struct
sys.path.insert(0,r'C:\Users\Apps\AppData\Local\Temp\adj9')
import an
from unicorn import *
import unicorn.arm64_const as arm64c
from unicorn.arm64_const import *
from capstone import *
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
JNI_NAMES={0x558:'GetArrayLength',0x580:'NewByteArray',0x5c0:'GetByteArrayElements',
 0x600:'ReleaseByteArrayElements',0x640:'GetByteArrayRegion',0x680:'SetByteArrayRegion',
 0x6c0:'GetBooleanArrayRegion'}
SOMAP=0x0; SOSZ=0x200000
STACK=0x40000000; STACKSZ=0x800000
HEAP=0x50000000; HEAPSZ=0x800000
ENV=0x60000000; TABLE=0x60010000
TLS=0x70000000; DATA=0x30000000; SRET=0x7fff0000
STUBS=0x80000000
ALLOW={0x147d3c,0xae94,0x100094}
mu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
mu.mem_map(SOMAP,SOSZ); mu.mem_write(SOMAP,an.D[:SOSZ])
mu.mem_map(STACK,STACKSZ); mu.mem_map(HEAP,HEAPSZ); mu.mem_map(ENV,0x20000)
mu.mem_map(TLS,0x1000); mu.mem_map(DATA,0x200000); mu.mem_map(SRET,0x10000)
mu.mem_map(STUBS,0x20000)
mu.mem_write(STUBS,struct.pack('<I',0xd65f03c0)*0x8000)
for i in range(512): mu.mem_write(TABLE+i*8,struct.pack('<Q',STUBS+i*0x10))
mu.mem_write(ENV,struct.pack('<Q',TABLE))
mu.mem_write(TLS+0x28,struct.pack('<Q',0x1122334455667788))
mu.reg_write(UC_ARM64_REG_TPIDR_EL0,TLS)
hp=[HEAP+0x1000]
def calloc(n,sz):
    p=hp[0]; sz=max(n*sz,16); hp[0]+=(sz+0x3f)&~0x3f
    mu.mem_write(p,b'\0'*sz); return p
ST=DATA+0x1000
sp=STACK+STACKSZ-0x4000
mu.reg_write(UC_ARM64_REG_SP,sp)
for r,v in ((UC_ARM64_REG_X0,ENV),(UC_ARM64_REG_X1,sp+0x40),(UC_ARM64_REG_X2,ST),
            (UC_ARM64_REG_X3,ST),(UC_ARM64_REG_X4,ENV),(UC_ARM64_REG_X5,0)):
    mu.reg_write(r,v)
mu.reg_write(UC_ARM64_REG_LR,SRET)
mu.mem_write(ST,bytes((i*7+3)&0xff for i in range(0x200)))
recs=[]; calls=[]; fold=[]; jni=[]; RING=[]
def R(r): return mu.reg_read(r)
def hook_code(u,addr,size,ud):
    if STUBS<=addr<STUBS+0x20000:
        idx=(addr-STUBS)>>4
        jni.append((idx,u.reg_read(UC_ARM64_REG_X2),u.reg_read(UC_ARM64_REG_X3)))
        u.reg_write(UC_ARM64_REG_X0,0)
        u.reg_write(UC_ARM64_REG_PC,R(UC_ARM64_REG_LR)); return
    try: i=next(md.disasm(u.mem_read(addr,size),addr))
    except StopIteration: u.emu_stop(); return
    m,op=i.mnemonic,i.op_str
    if addr==0x148b90:
        u.reg_write(UC_ARM64_REG_X0,calloc(R(UC_ARM64_REG_X0),R(UC_ARM64_REG_X1)))
        u.reg_write(UC_ARM64_REG_PC,R(UC_ARM64_REG_LR)); return
    if m=='bl':
        u.reg_write(UC_ARM64_REG_LR,addr+4)
        t=int(op.split('#')[1],16)
        if t==0x147d3c:
            recs.append([R(UC_ARM64_REG_X0),R(UC_ARM64_REG_X1)&0xffffffff,R(UC_ARM64_REG_X2)])
        elif t==0x100094:
            fold.append([R(UC_ARM64_REG_X0),R(UC_ARM64_REG_X1),R(UC_ARM64_REG_X2)&0xffffffff]+[R(getattr(arm64c,'UC_ARM64_REG_X%d'%k)) for k in range(3,11)])
            u.emu_stop(); return
        elif t not in ALLOW:
            calls.append((addr,t)); u.reg_write(UC_ARM64_REG_X0,0)
            u.reg_write(UC_ARM64_REG_PC,R(UC_ARM64_REG_LR)); return
    elif m=='blr':
        rn=op.strip()
        t=R(getattr(arm64c,'UC_ARM64_REG_'+rn[0].upper()+rn[1:]))
        if STUBS<=t<STUBS+0x20000:
            jni.append(((t-STUBS)>>4,R(UC_ARM64_REG_X2),R(UC_ARM64_REG_X3)))
        else: calls.append((addr,'blr '+rn))
        u.reg_write(UC_ARM64_REG_X0,0)
        u.reg_write(UC_ARM64_REG_PC,R(UC_ARM64_REG_LR)); return
    if addr==0x12cbe8:
        u.mem_write(R(UC_ARM64_REG_X29)-0x18,struct.pack('<I',1))
    RING.append((addr,m,op,R(UC_ARM64_REG_X30)))
    if len(RING)>30: RING.pop(0)
    if addr in (SRET,): u.emu_stop()
mu.hook_add(UC_HOOK_CODE,hook_code)
try: mu.emu_start(0x12cb74,SRET)
except UcError as e: print('ERR',e,'pc=%#x'%R(UC_ARM64_REG_PC))
print('pc=%#x'%R(UC_ARM64_REG_PC))
print('stubbed bl:',[(hex(a),hex(t) if isinstance(t,int) else t) for a,t in calls])
print('jni idx used:',sorted(set(j[0] for j in jni)))
print('nodes:',len(recs))
for k,(o,l,d) in enumerate(recs):
    print('%2d out=%#x len=%d data=%#x  data[:32]=%s'%(k,o,l,d,bytes(mu.mem_read(d,min(l,32))).hex()))
print('fold call:',[[hex(x) if isinstance(x,int) else x for x in f] for f in fold])
for a,m,op,x30 in RING: print('  %#x %-6s %-34s x30=%#x'%(a,m,op,x30))
