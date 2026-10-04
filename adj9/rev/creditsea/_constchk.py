"""_constchk.py — which constant fails on the LIVE blobs?"""
import sys, os, re
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,HERE); sys.path.insert(0,os.path.dirname(HERE))
sys.path.insert(0,'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import whiten_decoder as WD
b=open('adj9_cap_live_tarsan.log','rb').read().decode('utf-8','replace')
blobs=[]
for m in re.finditer(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]+)", b):
    h=m.group(1).lower()
    if len(h)==384 and h not in blobs: blobs.append(h)
for h in blobs:
    d=WD.decode_blob(bytes.fromhex(h))
    rec=d['record']
    print('record layout:')
    print('  magic  [0:3)   =', rec[0:3].hex(), '(expect 010008)')
    print('  flag19 [19]    =', hex(rec[19]), '(expect 0x02)')
    print('  flag24 [24]    =', hex(rec[24]), '(expect 0x03)')
    print('  cert   [25:45) =', rec[25:45].hex())
    print('  flag45 [45]    =', hex(rec[45]), '(expect 0x04)')
    print('  flag78 [78]    =', hex(rec[78]), '(expect 0x05)')
    print('  sha256 [79:111)=', rec[79:111].hex()[:32],'...')
    print('  tag111 [111:114)=', rec[111:114].hex(), '(expect 060107)')
    print('  zeros [114:128)=', rec[114:128].hex()[:20])
    print('  tail2 [128:130)=', rec[128:130].hex(), '(expect 0000)')
    print('  ones  [130:144)=', rec[130:144].hex()[:20], '(expect 0e...)')
    print('  consts_ok      =', d['consts_ok'])
    print()
