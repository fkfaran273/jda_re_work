import sys
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S
seeds=[0x19d4c97e,0xe1c3efdd,0x0f476009,0xf516aa41,0x12b21e6b,0x94904031,0x4076156b,0xafcaca2e,0x985f5c11,0x6a896959,0x96821afb]
for Sx in seeds:
    st=Sx
    st16=[]; perm=[0]*16
    for k in range(16):
        r=S._step(st); st=r; j=r%(k+1); perm[k],perm[j]=perm[j],k
    st=Sx
    seq=[]
    for i in range(16):
        if i%2==0: st=S._step(st)
        seq.append(st)
    pre=[]; st=Sx
    # redo properly
    st=Sx
    for i in range(16):
        if i%2==0: st=S._step(st)
        r=st
        v=(r>>16)&0xffff if i%2==0 else r
        pos=15-perm[i]
        pre.append(((v&((1<<pos)-1))|(1<<pos))&0xffff)
    tr=S._transpose16(pre)
    d4=[int.from_bytes(b''.join(x.to_bytes(2,'little') for x in tr)[i:i+4],'big') for i in range(0,32,4)]
    # raw16 states
    st=Sx; raw=[]
    for i in range(16):
        if i%2==0: st=S._step(st)
        raw.append(st)
    packed=b''.join(x.to_bytes(2,'little') for x in tr)
    print(f"S={Sx:#010x}")
    print('  state16:', ' '.join('%08x'%v for v in seq))
    print('  rawpre :', ' '.join('%04x'%v for v in pre))
    print('  perm   :', perm)
    print('  transp :', ' '.join('%04x'%v for v in tr))
    print('  d4 words:', ' '.join('%08x'%w for w in d4))
    print('  d4[16:32]:', packed[16:32].hex())
    src=[int.from_bytes(packed[i:i+2],'little') for i in range(16,32,2)]
    print('  source  :', ' '.join('%04x'%v for v in src))
    print('  targets :', ' '.join('%04x'%S._whitener_word(0x40+(i&7),src) for i in range(12)))
