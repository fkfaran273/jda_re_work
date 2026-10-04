import json, os, struct, sys, time
sys.path.insert(0,'.')
import vm_inverse as VI
import F as FREG
import mint_pipeline as M

# corpus row 0 descriptors
descs0 = VI.corpus_descs(0, None)
sec0,_ = VI.corpus_row(0)
print('sec', sec0)
# real region for all_signings row0
asg=json.load(open('all_signings.json'))
r=asg[0]
d0=bytes.fromhex(r['d0']); d2=bytes.fromhex(r['d2']); d4=bytes.fromhex(r['d4'])
t0=time.time()
c = VI.capture(sec0, VI.corpus_descs(0,(d0,d2,d4)))
print('status',c['status'],'%.1fs'%(time.time()-t0))
rec=c['record']
print('rec hex', rec.hex())
ph3=json.load(open('pair_h3.json'))
want=bytes.fromhex(ph3[0]['blob'])
print('blob match', c['blob'].hex()==want.hex())
print('block', rec[46:78].hex())
print('want ', want[46:78].hex())
