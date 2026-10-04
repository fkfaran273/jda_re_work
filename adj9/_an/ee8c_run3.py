import sys,re,struct
sys.path.insert(0,r'C:\Users\Apps\AppData\Local\Temp\adj9')
import an
import unicorn.arm64_const as arm64c
from unicorn import *
from capstone import *
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)

def R(r): return MU.reg_read(r)
def hx(r): return getattr(arm64c,'UC_ARM64_REG_'+r.upper())

HPAT=bytes(range(0x10,0x30))          # "H"  = 32 bytes read out of the caller's byte[]
CPAT=bytes((i*3+1)&0xff for i in range(32))  # 32 bytes "recomputed" by 0xd91d4

def run(match):
    global MU
    MU=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    MU.mem_map(0,0x200000); MU.mem_write(0,an.D[:0x200000])
    MU.mem_map(0x40000000,0x400000); MU.mem_map(0x50000000,0x400000)
    MU.mem_map(0x60000000,0x20000); MU.mem_map(0x70000000,0x1000)
    MU.mem_map(0x30000000,0x200000); MU.mem_map(0x7fff0000,0x1000); MU.mem_map(0x80000000,0x20000)
    MU.mem_write(0x80000000,struct.pack('<I',0xd65f03c0)*0x8000)
    for i in range(512): MU.mem_write(0x60010000+i*8,struct.pack('<Q',0x80000000+i*0x10))
    MU.mem_write(0x60000000,struct.pack('<Q',0x60010000))
    MU.mem_write(0x70000028,struct.pack('<Q',0x1122334455667788))
    MU.reg_write(arm64c.UC_ARM64_REG_TPIDR_EL0,0x70000000)
    hp=[0x50001000]
    def calloc(n,s):
        p=hp[0]; sz=max(n*s,16); hp[0]+=(sz+0x3f)&~0x3f
        MU.mem_write(p,b'\0'*sz); return p
    ST=0x30001000; sp=0x40100000
    MU.reg_write(arm64c.UC_ARM64_REG_SP,sp)
    MU.mem_write(ST,bytes((i*7+3)&0xff for i in range(0x200)))
    MU.reg_write(arm64c.UC_ARM64_REG_X0,0x60000000)
    MU.reg_write(arm64c.UC_ARM64_REG_X1,0x60002000)   # claims jobject
    MU.reg_write(arm64c.UC_ARM64_REG_X2,ST)
    MU.reg_write(arm64c.UC_ARM64_REG_X3,0x60003000)   # H jobject
    MU.reg_write(arm64c.UC_ARM64_REG_LR,0x7fff0000)
    log=[]; cnt=[0]; stw=[]; TR=[]
    def hook(u,addr,size,ud):
        cnt[0]+=1
        TR.append(addr)
        if len(TR)>60: TR.pop(0)
        if cnt[0]>400000:
            log.append(('LOOP',addr)); u.emu_stop(); return
        if 0x80000000<=addr<0x80020000:
            u.reg_write(arm64c.UC_ARM64_REG_X0,0); u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
        if addr==0x7fff0000: u.emu_stop(); return
        i=next(md.disasm(u.mem_read(addr,size),addr))
        m,o=i.mnemonic,i.op_str
        if m=='bl':
            u.reg_write(arm64c.UC_ARM64_REG_LR,addr+4)
            t=int(o.split('#')[1],16)
            if t==0x9dc78:                       # (env, Hjob, &buf, &len)
                p=calloc(1,32); u.mem_write(p,HPAT)
                u.mem_write(R(arm64c.UC_ARM64_REG_X3),struct.pack('<Q',p))
                u.mem_write(R(arm64c.UC_ARM64_REG_X4),struct.pack('<Q',32))
                log.append(('9dc78',hex(p)))
                u.reg_write(arm64c.UC_ARM64_REG_X0,0)
            elif t==0xa4f50:                     # (arg1, env, jobj, &out)
                p=calloc(1,64); u.mem_write(R(arm64c.UC_ARM64_REG_X4),struct.pack('<Q',p))
                log.append(('a4f50',hex(p)))
                u.reg_write(arm64c.UC_ARM64_REG_X0,0)
            elif t==0xd91d4:                     # (env,arg1,jobj,a,b,&buf,&len)
                p=calloc(1,32); u.mem_write(p,CPAT)
                u.mem_write(R(arm64c.UC_ARM64_REG_X5),struct.pack('<Q',p))
                u.mem_write(R(arm64c.UC_ARM64_REG_X6),struct.pack('<Q',32))
                log.append(('d91d4',hex(p)))
                u.reg_write(arm64c.UC_ARM64_REG_X0,0)
            elif t==0xd7aac:
                log.append(('d7aac','Hjob=%#x'%R(arm64c.UC_ARM64_REG_X3)))
                u.reg_write(arm64c.UC_ARM64_REG_X0,0)
            else:
                log.append((hex(t),'stub'))
                u.reg_write(arm64c.UC_ARM64_REG_X0,0)
            u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
        if m=='blr':
            rn=o.strip(); t=R(hx(rn))
            if 0x80000000<=t<0x80020000:
                u.reg_write(arm64c.UC_ARM64_REG_LR,addr+4); u.reg_write(arm64c.UC_ARM64_REG_PC,t); return
            u.reg_write(arm64c.UC_ARM64_REG_X0,0); u.reg_write(arm64c.UC_ARM64_REG_PC,R(arm64c.UC_ARM64_REG_LR)); return
        if addr==0xef78:
            log.append(('STATE','%#x'%R(arm64c.UC_ARM64_REG_X8)))
        if addr==0xf89c:
            p1=R(arm64c.UC_ARM64_REG_X8); p2=R(arm64c.UC_ARM64_REG_X9)
            try: b1=bytes(u.mem_read(p1,1)); b2=bytes(u.mem_read(p2,1))
            except: b1=b2=b'?'
            log.append(('CMP',hex(p1),hex(p2),b1.hex(),b2.hex()))
    MU.hook_add(UC_HOOK_CODE,hook)
    MU.hook_add(UC_HOOK_MEM_WRITE,lambda u,ty,ad,sz,v,ud: stw.append((ad,sz)))
    try: MU.emu_start(0xee8c,0x7fff0000)
    except UcError as e: log.append(('ERR',str(e),'pc=%#x'%R(arm64c.UC_ARM64_REG_PC)))
    w0=R(arm64c.UC_ARM64_REG_W0)
    return log,cnt[0],w0,sorted(set(a for a,_ in stw)),[hex(a) for a in TR],hex(R(arm64c.UC_ARM64_REG_PC))

for m in (True,False):
    if not m: CPAT=bytes((i*3+2)&0xff for i in range(32))
    else:    CPAT=bytes((i*3+1)&0xff for i in range(32))
    log,n,w0,writes,tr,pc=run(m)
    print('===== H %s computed  -> instrs=%d ret=%d' % ('MATCHES' if m else 'DIFFERS', n, w0&0xffffffff))
    for e in log[:60]: print('   ',e)
    print('   finalpc',pc,'tail',tr)
    print('   writes to st region:',[hex(a) for a in writes if 0x30001000<=a<0x30001200])
