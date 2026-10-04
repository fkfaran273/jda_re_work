import sys,re,struct
sys.path.insert(0,r'C:\Users\Apps\AppData\Local\Temp\adj9')
import an
import unicorn.arm64_const as arm64c
from unicorn import *
from capstone import *
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
mu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
mu.mem_map(0,0x200000); mu.mem_write(0,an.D[:0x200000])
mu.mem_map(0x40000000,0x400000); mu.mem_map(0x50000000,0x400000)
mu.mem_map(0x60000000,0x20000); mu.mem_map(0x70000000,0x1000)
mu.mem_map(0x30000000,0x200000); mu.mem_map(0x7fff0000,0x1000); mu.mem_map(0x80000000,0x20000)
mu.mem_write(0x80000000,struct.pack('<I',0xd65f03c0)*0x8000)
for i in range(512): mu.mem_write(0x60010000+i*8,struct.pack('<Q',0x80000000+i*0x10))
mu.mem_write(0x60000000,struct.pack('<Q',0x60010000))
mu.mem_write(0x70000028,struct.pack('<Q',0x1122334455667788))
mu.reg_write(arm64c.UC_ARM64_REG_TPIDR_EL0,0x70000000)
hp=[0x50001000]
def calloc(n,s):
    p=hp[0]; sz=max(n*s,16); hp[0]+=(sz+0x3f)&~0x3f
    mu.mem_write(p,b'\0'*sz); return p
ST=0x30001000
sp=0x40100000
mu.reg_write(arm64c.UC_ARM64_REG_SP,sp)
for r,v in ((arm64c.UC_ARM64_REG_X0,0x60000000),(arm64c.UC_ARM64_REG_X1,sp+0x40),(arm64c.UC_ARM64_REG_X2,ST),
            (arm64c.UC_ARM64_REG_X3,ST),(arm64c.UC_ARM64_REG_X4,0x60000000),(arm64c.UC_ARM64_REG_X5,0)):
    mu.reg_write(r,v)
mu.reg_write(arm64c.UC_ARM64_REG_LR,0x7fff0000)
mu.mem_write(ST,bytes((i*7+3)&0xff for i in range(0x200)))
recs=[];disp=[];exec_set=[];TR=[]
def R(r): return mu.reg_read(r)
def hx(r): return getattr(arm64c,'UC_ARM64_REG_'+r.upper())
def hook(u,addr,size,ud):
    TR.append(addr)
    if len(TR)>400: TR.pop(0)
    if 0x80000000<=addr<0x80020000:
        u.reg_write(arm64c.UC_ARM64_REG_X0,0); u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
    if addr==0x7fff0000: u.emu_stop(); return
    i=next(md.disasm(u.mem_read(addr,size),addr))
    m,o=i.mnemonic,i.op_str
    if m=='bl':
        u.reg_write(arm64c.UC_ARM64_REG_LR,addr+4)
        t=int(o.split('#')[1],16)
        if t==0x148b90:
            u.reg_write(arm64c.UC_ARM64_REG_X0,calloc(R(arm64c.UC_ARM64_REG_X0),R(arm64c.UC_ARM64_REG_X1)))
        elif t==0x147d3c:
            recs.append((addr,R(arm64c.UC_ARM64_REG_X1)&0xffffffff,R(arm64c.UC_ARM64_REG_X2)))
        elif t==0x100094:
            print('FOLD at %#x args x0=%#x x1=%#x w2=%d'%(addr,R(arm64c.UC_ARM64_REG_X0),R(arm64c.UC_ARM64_REG_X1),R(arm64c.UC_ARM64_REG_X2)))
            print('   x29=%#x sp=%#x'%(R(arm64c.UC_ARM64_REG_X29),R(arm64c.UC_ARM64_REG_SP)))
            print('   x0..x17:',[('%#x'%R(hx('x%d'%k))) for k in range(18)])
            print('   stack:',[('%#x'%v) for v in struct.unpack('<8Q',u.mem_read(R(arm64c.UC_ARM64_REG_SP),0x40))])
            u.emu_stop(); return
        else:
            u.reg_write(arm64c.UC_ARM64_REG_X0,0)
        u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
    if m=='blr':
        rn=o.strip(); t=R(hx(rn))
        if 0x80000000<=t<0x80020000:
            u.reg_write(arm64c.UC_ARM64_REG_LR,addr+4); u.reg_write(arm64c.UC_ARM64_REG_PC,t); return
        u.reg_write(arm64c.UC_ARM64_REG_X0,0); u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
    if addr==0x12cc00: print('cmp w8,#0 : w8=%d [x29-0x18]=%s'%(R(arm64c.UC_ARM64_REG_W8),mu.mem_read(R(arm64c.UC_ARM64_REG_X29)-0x18,4).hex()))
    if addr==0x12cc2c: print('csel x8=%#x x10=%#x x9=%#x'%(R(arm64c.UC_ARM64_REG_X8),R(arm64c.UC_ARM64_REG_X10),R(arm64c.UC_ARM64_REG_X9)))
    if addr==0x12cc34: disp.append(R(arm64c.UC_ARM64_REG_X6))
    exec_set.append(addr)
mu.hook_add(UC_HOOK_CODE,hook)
try: mu.emu_start(0x12cb74,0x7fff0000)
except UcError as e: print('ERR',e,'pc=%#x'%R(arm64c.UC_ARM64_REG_PC))
print('disp states:',[hex(x) for x in disp])
print('trace tail:',[hex(a) for a in TR[-70:]])
print('nodes:',[(hex(a),l,hex(d)) for a,l,d in recs])
print('0x12d39c executed?',0x12d39c in exec_set,' 0xae94 executed?',0xae94 in exec_set)
