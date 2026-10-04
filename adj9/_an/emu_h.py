import sys,struct
sys.path.insert(0,r'C:\Users\Apps\AppData\Local\Temp\adj9')
import an
import unicorn.arm64_const as arm64c
from unicorn import *
from capstone import *
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
SOMAP=0x0;SOSZ=0x200000
STACK=0x40000000;STACKSZ=0x200000
HEAP=0x50000000;ENV=0x60000000;TABLE=0x60010000
TLS=0x70000000;DATA=0x30000000;SRET=0x7fff0000;STUBS=0x80000000
HBUF=0x30010000
HPAT=bytes(range(0xA0,0xA0+64))
mu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
mu.mem_map(SOMAP,SOSZ);mu.mem_write(SOMAP,an.D[:SOSZ])
for a,n in ((STACK,STACKSZ),(HEAP,0x100000),(ENV,0x20000),(TLS,0x1000),(DATA,0x200000),(SRET,0x10000),(STUBS,0x20000)):
    mu.mem_map(a,n)
mu.mem_write(STUBS,struct.pack('<I',0xd65f03c0)*0x8000)
for i in range(512): mu.mem_write(TABLE+i*8,struct.pack('<Q',STUBS+i*0x10))
mu.mem_write(ENV,struct.pack('<Q',TABLE))
mu.mem_write(TLS+0x28,struct.pack('<Q',0x1122334455667788))
mu.reg_write(arm64c.UC_ARM64_REG_TPIDR_EL0,TLS)
HANDLED=[]
sp=STACK+STACKSZ-0x4000
mu.reg_write(arm64c.UC_ARM64_REG_SP,sp)
STATUS=DATA+0x100; L40=DATA+0x200; L30=DATA+0x300
mu.reg_write(arm64c.UC_ARM64_REG_X0,STATUS)
mu.reg_write(arm64c.UC_ARM64_REG_X1,ENV)
mu.reg_write(arm64c.UC_ARM64_REG_X2,0xAA000001)   # fake H jobject
mu.reg_write(arm64c.UC_ARM64_REG_X3,L40)
mu.reg_write(arm64c.UC_ARM64_REG_X4,L30)
mu.reg_write(arm64c.UC_ARM64_REG_LR,SRET)
mu.mem_write(STATUS,struct.pack('<i',0))
def R(r): return mu.reg_read(r)
def hx(r): return getattr(arm64c,'UC_ARM64_REG_'+r.upper())
def hook(u,addr,size,ud):
    if STUBS<=addr<STUBS+0x20000:
        idx=(addr-STUBS)>>4
        if idx==171:      # 0x558 GetArrayLength
            u.reg_write(arm64c.UC_ARM64_REG_X0,32)
            print('  JNI GetArrayLength arr=%#x -> 32'%(R(arm64c.UC_ARM64_REG_X2),))
            u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
        if idx==200:      # 0x640 GetByteArrayRegion
            arr=R(arm64c.UC_ARM64_REG_X2); st=R(arm64c.UC_ARM64_REG_X3)&0xffffffff
            ln=R(arm64c.UC_ARM64_REG_X4); buf=R(arm64c.UC_ARM64_REG_X5)
            print('  JNI GetByteArrayRegion arr=%#x start=%d len=%d buf=%#x'%(arr,st,ln,buf))
            u.mem_write(buf,HPAT[:ln]); HANDLED.append(('GetByteArrayRegion',buf,ln))
            u.reg_write(arm64c.UC_ARM64_REG_X0,0)
        else:
            print('  JNI idx',idx,'x2=%#x x3=%#x x4=%#x x5=%#x'%(R(arm64c.UC_ARM64_REG_X2),R(arm64c.UC_ARM64_REG_X3),R(arm64c.UC_ARM64_REG_X4),R(arm64c.UC_ARM64_REG_X5)))
            u.reg_write(arm64c.UC_ARM64_REG_X0,0)
        u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
    try: i=next(md.disasm(u.mem_read(addr,size),addr))
    except StopIteration: u.emu_stop(); return
    m,op=i.mnemonic,i.op_str
    if m=='bl':
        u.reg_write(arm64c.UC_ARM64_REG_LR,addr+4)
        t=int(op.split('#')[1],16)
        if t not in (0x9dc78,0x9c724):
            print('  CALL %#x (x0=%#x x1=%#x x2=%#x x3=%#x)'%(t,R(arm64c.UC_ARM64_REG_X0),R(arm64c.UC_ARM64_REG_X1),R(arm64c.UC_ARM64_REG_X2),R(arm64c.UC_ARM64_REG_X3)))
            u.reg_write(arm64c.UC_ARM64_REG_X0,0)
            u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
    elif m=='blr':
        rn=op.strip(); t=R(hx(rn))
        if STUBS<=t<STUBS+0x20000:
            u.reg_write(arm64c.UC_ARM64_REG_LR,addr+4)
            u.reg_write(arm64c.UC_ARM64_REG_PC,t); return
        print('  BLR %s -> %#x'%(rn,t))
        u.reg_write(arm64c.UC_ARM64_REG_X0,0)
        u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
    if addr in (0x9df38,0x9df48):
        print('  @%#x x28=%#x x24=%#x x19=%#x x25=%#x x13=%#x'%(addr,R(arm64c.UC_ARM64_REG_X28),R(arm64c.UC_ARM64_REG_X24),R(arm64c.UC_ARM64_REG_X19),R(arm64c.UC_ARM64_REG_X25),R(arm64c.UC_ARM64_REG_X13)))
    if addr==SRET: u.emu_stop()
mu.hook_add(UC_HOOK_CODE,hook)
try: mu.emu_start(0x9dc78,SRET)
except UcError as e:
    print('ERR',e,'pc=%#x'%R(arm64c.UC_ARM64_REG_PC))
    for n in range(28,31): print('   x%d=%#x'%(n,R(getattr(arm64c,'UC_ARM64_REG_X%d'%n))))
print('pc=%#x'%R(arm64c.UC_ARM64_REG_PC))
for nm,buf,ln in HANDLED:
    print('buf %#x: %s'%(buf,bytes(mu.mem_read(buf,ln)).hex()))
print('status@%#x = %s'%(STATUS,bytes(mu.mem_read(STATUS,8)).hex()))
print('L40=%s'%bytes(mu.mem_read(L40,0x40)).hex())
print('L30=%s'%bytes(mu.mem_read(L30,0x40)).hex())
print('stack[HBPAT region] search:')
