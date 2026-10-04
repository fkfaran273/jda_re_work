"""_seeded.py — reproduce the LIVE blobs using each blob's OWN recovered seed.
This is exactly what desc10_58.validate_against_device does for the old capture."""
import sys, os, re, datetime
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,HERE); sys.path.insert(0,os.path.dirname(HERE))
sys.path.insert(0,'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import whiten_decoder as WD
from testbed import build_descs, run_vm
import desc10_58 as D
b=open('adj9_cap_live_tarsan.log','rb').read().decode('utf-8','replace')
blobs=[]
for m in re.finditer(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]+)", b):
    h=m.group(1).lower()
    if len(h)==384 and h not in blobs: blobs.append(h)
maps=[]
for m in re.finditer(r'map_size=(\d+)\r?\nmap_toString=\{', b):
    seg=b[m.end():m.end()+6000]; end=seg.find('}'); raw=seg[:end]
    maps.append(dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw)))
import mint_pipeline as MP
ok=0; tot=0
for h in blobs:
    blob_b=bytes.fromhex(h)
    dec=WD.decode_blob(blob_b)
    S=dec['F_seed']
    # recover head
    import signer_simple as sg
    d4w=None
    import F as Fmod
    d4w=Fmod._d4_words(S)
    for a in (0x2b,):
        w=Fmod._d0_words(d4w, head=(a,))
        if WD.head_words(w)==dec['head']:
            d0=b''.join(x.to_bytes(4,'big') for x in w)
            break
    else:
        print('head not recovered'); continue
    d4=b''.join(x.to_bytes(4,'big') for x in d4w)
    d2=dec['d2w'].to_bytes(4,'big')
    # nearest genuine map for the claims
    kind='attribution'
    cand=[m for m in maps if m.get('activity_kind')==kind]
    for mp_ in cand:
        raw,_p=D.claims_for_law_58(mp_, kind)
        descs=build_descs(0, raw, d0, d4, d2)
        out,status=run_vm(dec['second'] if 'second' in dec else 0, descs, max_steps=60_000_000)
        # need the right second; get from header inversion
        break
    # invert header for the second
    sec=None
    for s in range(1790740000,1790743000):
        if MP.make_header(s).hex()==h[:32]: sec=s; break
    if sec is None: continue
    for mp_ in cand:
        raw,_p=D.claims_for_law_58(mp_, kind)
        descs=build_descs(sec, raw, d0, d4, d2)
        out,status=run_vm(sec, descs, max_steps=60_000_000)
        n=sum(1 for x,y in zip(out,blob_b) if x==y)
        tot+=1
        if bytes(out)==blob_b:
            ok+=1; print('  *** LIVE BYTE-EXACT second=%d'%sec)
        else:
            print('  second=%d -> %d/192 status=%s'%(sec,n,status))
        break
print()
print('LIVE BYTE-EXACT: %d / %d'%(ok,tot))
