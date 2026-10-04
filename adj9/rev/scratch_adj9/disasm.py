import sys
sys.path.insert(0,r'C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool')
import adj9_signer as S
for i in S.INS:
    if 0x143f00<=i.address<=0x144200:
        print('%08x  %-8s %s'%(i.address,i.mnemonic,i.op_str))
