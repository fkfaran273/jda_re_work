import json, os, struct, sys, time
sys.path.insert(0,'.')
import vm_inverse as VI
import F as FREG

asg=json.load(open('all_signings.json'))
r=asg[0]
d0=bytes.fromhex(r['d0']); d2=bytes.fromhex(r['d2']); d4=bytes.fromhex(r['d4'])
sec0,_ = VI.corpus_row(0)

def run(sec, region):
    c=VI.capture(sec, VI.corpus_descs(0, region))
    rec=c['record']
    # locate block: find the 32 bytes after the d9 cert marker
    i=rec.find(bytes.fromhex('fad0f10d60f93c17937b2f1eb6c09691ae7d74bd'))
    blk=rec[i+21:i+53] if i>=0 else None
    return c['status'], blk, rec[i-1:i+1].hex() if i>=0 else None, rec[:16].hex()

import random
# A: vary S, fixed second
print('--- vary S, fixed second ---')
for S in (0xf516aa41, 0x00000000, 0xffffffff, 0x12345678, 0xf516aa42):
    d4w=FREG._d4_words(S)
    d0w=FREG._d0_words(d4w, head=FREG.HEAD_FIRST)
    reg=(b''.join(struct.pack('>I',w) for w in d0w), struct.pack('>I', int.from_bytes(S.to_bytes(4,'big'),'little')), b''.join(struct.pack('>I',w) for w in d4w))
    t0=time.time(); st,blk,mark,head=run(sec0, reg)
    print('S=%08x %-11s mark=%s head=%s block=%s (%.0fs)'%(S,st,mark,head,blk.hex() if blk else None, time.time()-t0), flush=True)

print('--- vary second, fixed S ---')
d4w=FREG._d4_words(0xf516aa41); d0w=FREG._d0_words(d4w, head=FREG.HEAD_FIRST)
reg=(b''.join(struct.pack('>I',w) for w in d0w), struct.pack('>I', int.from_bytes((0xf516aa41).to_bytes(4,'big'),'little')), b''.join(struct.pack('>I',w) for w in d4w))
for sec in (sec0, sec0+1, sec0+2, sec0+137):
    t0=time.time(); st,blk,mark,head=run(sec, reg)
    print('sec=%d %-11s mark=%s block=%s (%.0fs)'%(sec,st,mark,blk.hex() if blk else None, time.time()-t0), flush=True)
