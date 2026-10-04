"""_row8b.py — click row8 with DEVICE descriptors + our byte-exact desc10.

_correct the earlier bug: desc10 must be the PADDED 388 B (4-byte aligned),
matching the genuine d10 exactly.  Uses the device's own d0/d2/d4/d8/d9/d7.
"""
import binascii, json, multiprocessing as mp, os, struct, sys
sys.path.insert(0, '.')
import mint_pipeline as M
HERE = os.path.dirname(os.path.abspath(__file__))
_G = {}

def _init(descs, d10):
    import mint_pipeline as m
    _G['m'] = m; _G['blobs'] = set(json.load(open(os.path.join(HERE,'_genuine_blobs.json'))))
    _G['descs'] = descs; _G['d10'] = d10

def _try(sec):
    by = dict(_G['descs']); by[10] = (len(_G['d10'])//4, _G['d10'])
    try:
        blob, vm = _G['m'].finex_mint([by[i] for i in M.VA_ORDER], sec)
    except Exception:
        return None
    h = blob.hex()
    return (sec, h) if h in _G['blobs'] else None

def main():
    sig = json.load(open(os.path.join(HERE,'all_signings.json')))
    r8 = [r for r in sig if r['ev'] == 22272][0]
    gen = binascii.unhexlify(r8['d10'])
    d0=binascii.unhexlify(r8['d0']); d2=binascii.unhexlify(r8['d2'])
    d4=binascii.unhexlify(r8['d4']); d8=binascii.unhexlify(r8['d8'])
    d9=binascii.unhexlify(r8['d9']); d7=int(r8['d7'],16)
    print('using genuine padded d10 directly (388 B):', len(gen))
    descs={0:(36,d0),9:(5,d9),8:(4,d8),4:(8,d4),2:(1,d2),
           7:(1,struct.pack('>I',d7)),10:(0,b''),5:(1,b'\0'*4),
           6:(1,b'\0'*4),1:(0,b''),3:(0,b'')}
    secs=sorted(set(json.load(open(os.path.join(HERE,'_blob_seconds.json'))).values()))
    print('sweeping %d seconds (device descriptors + genuine d10)'%len(secs))
    hit=None
    with mp.Pool(14, initializer=_init, initargs=(descs,gen)) as pool:
        for res in pool.imap_unordered(_try, secs, chunksize=1):
            if res: hit=res; pool.terminate(); break
    if hit: print('*** ROW8 REPRODUCES: second=%d blob=%s'%(hit[0],hit[1][:64]))
    else:   print('*** ROW8 FAILS even with the device descriptors + its own d10')
    print('(if it fails, the row8 signing second is simply not among the 274)')

if __name__ == '__main__': main()
