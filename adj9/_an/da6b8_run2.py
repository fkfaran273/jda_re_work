import sys,re,struct
sys.path.insert(0,r'C:\Users\Apps\AppData\Local\Temp\adj9')
import an
import unicorn.arm64_const as arm64c
from unicorn import *
from capstone import *
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
P={v:(0x148a00+16*((k-1346016)//16)) for k,v in an.PLT.items()}

MU=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
MU.mem_map(0,0x200000); MU.mem_write(0,an.D[:0x200000])
MU.mem_map(0x40000000,0x800000); MU.mem_map(0x50000000,0x800000)
MU.mem_map(0x60000000,0x20000); MU.mem_map(0x70000000,0x1000)
MU.mem_map(0x30000000,0x200000); MU.mem_map(0x7fff0000,0x1000); MU.mem_map(0x80000000,0x20000)
MU.mem_write(0x80000000,struct.pack('<I',0xd65f03c0)*0x8000)
for i in range(600): MU.mem_write(0x60010000+i*8,struct.pack('<Q',0x80000000+i*0x10))
MU.mem_write(0x60000000,struct.pack('<Q',0x60010000))
MU.mem_write(0x70000028,struct.pack('<Q',0x1122334455667788))
MU.reg_write(arm64c.UC_ARM64_REG_TPIDR_EL0,0x70000000)
hp=[0x50001000]
def alloc(sz):
    sz=(sz+0xf)&~0xf
    p=hp[0]; hp[0]+=sz+0x10
    MU.mem_write(p,b'\0'*sz); return p
hp[0]=0x50001000
def R(r): return MU.reg_read(r)
def hx(r): return getattr(arm64c,'UC_ARM64_REG_'+r.upper())

ST=0x30001000
STIMG=bytes((i*11+5)&0xff for i in range(0x400))
MU.mem_write(ST,STIMG)
sp=0x40200000
MU.reg_write(arm64c.UC_ARM64_REG_SP,sp)
MU.reg_write(arm64c.UC_ARM64_REG_X0,0x60000000)   # env
MU.reg_write(arm64c.UC_ARM64_REG_X1,0x60002000)   # claims jobject
MU.reg_write(arm64c.UC_ARM64_REG_X2,0x60003000)   # H jobject
MU.reg_write(arm64c.UC_ARM64_REG_X3,ST)
MU.reg_write(arm64c.UC_ARM64_REG_LR,0x7fff0000)

cnt=[0]; calls=[]; stw=[]
STOP=set()
def hook(u,addr,size,ud):
    cnt[0]+=1
    if cnt[0]>3000000: u.emu_stop(); return
    if 0x80000000<=addr<0x80020000:
        u.reg_write(arm64c.UC_ARM64_REG_X0,0); u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
    if addr==0x7fff0000: u.emu_stop(); return
    if addr in STOP: u.emu_stop(); return
    i=next(md.disasm(u.mem_read(addr,size),addr))
    m,o=i.mnemonic,i.op_str
    if m=='bl':
        t=int(o.split('#')[1],16)
        u.reg_write(arm64c.UC_ARM64_REG_LR,addr+4)
        nm=P.get(t)
        if nm is None:
            calls.append((hex(addr),'INTERNAL %#x'%t))   # let it run
            return
        if nm in ('malloc','calloc','realloc','strdup','memcpy','memset','__memcpy_chk'):
            a=[R(arm64c.UC_ARM64_REG_X0),R(arm64c.UC_ARM64_REG_X1),R(arm64c.UC_ARM64_REG_X2)]
            p=alloc(max(a[0]*max(a[1],1),1) if nm in('malloc','calloc') else max(a[1],1))
            if nm in ('memcpy','memset','__memcpy_chk'):
                try: MU.mem_write(p,bytes(u.mem_read(a[2] if nm!='memset' else a[0],a[1])))
                except: pass
            u.reg_write(arm64c.UC_ARM64_REG_X0,p)
            calls.append((hex(addr),nm))
        elif nm in ('free','__stack_chk_fail','strlen','strcmp','strchr','rand','srand','time','__cxa_finalize','__cxa_atexit','memset'):
            u.reg_write(arm64c.UC_ARM64_REG_X0,0)
            calls.append((hex(addr),nm))
        u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
    if m=='blr':
        rn=o.strip(); t=R(hx(rn))
        if 0x80000000<=t<0x80020000:
            u.reg_write(arm64c.UC_ARM64_REG_LR,addr+4); u.reg_write(arm64c.UC_ARM64_REG_PC,t); return
        calls.append((hex(addr),'JNI %s'%o))
        u.reg_write(arm64c.UC_ARM64_REG_X0,0)
        u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
MU.hook_add(UC_HOOK_CODE,hook)
def mh(u,ty,ad,sz,v,ud):
    if ST<=ad<ST+0x400: stw.append((ad,sz,v))
MU.hook_add(UC_HOOK_MEM_WRITE,mh)
try: MU.emu_start(0xda6b8,0x7fff0000,count=3000000)
except UcError as e: print('ERR',e,'pc=%#x'%R(arm64c.UC_ARM64_REG_PC))
print('instrs',cnt[0],'finalpc=%#x'%R(arm64c.UC_ARM64_REG_PC))
seen=[]
for c in calls:
    if not seen or seen[-1]!=c: seen.append(c)
print('call sequence:')
for c in seen: print('  ',c)
print('distinct internal callees:',sorted(set(c[1] for c in calls if c[1].startswith('INTERNAL'))))
print('--- writes into st:')
agg={}
for ad,sz,v in stw: agg.setdefault(ad,[]).append((sz,v))
for ad in sorted(agg):
    print('  +0x%03x  n=%d  %s'%(ad-ST,len(agg[ad]),[ (s,hex(x) if x>0x1000 else x) for s,x in agg[ad][:6]]))
newimg=bytes(MU.mem_read(ST,0x120))
print('st+0x20..0x50 :',newimg[0x20:0x50].hex())
print('st+0xf0..0x120 :',newimg[0xf0:0x120].hex())
