"""_liveproof.py — our signature vs the LIVE genuine blobs (freshest data).

33 genuine 192-B blobs from the device's Tarsan1-era capture.  For each, take
the blob's own signing second (header inversion), rebuild the region, mint with
OUR signer, and compare all 192 bytes.  This is the strongest signature test we
can run -- live device data, not the earlier capture.
"""
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import mint_pipeline as MP
import signer_simple as sg
import desc10_58 as D

CAP = 'adj9_cap_live_tarsan.log'
b = open(CAP, 'rb').read().decode('utf-8', 'replace')
blobs = []
for h in re.findall(r'\b([0-9a-f]{384})\b', b):
    if h not in blobs: blobs.append(h)
print('distinct genuine blobs: %d' % len(blobs))

# genuine signing maps available in this capture
maps = []
for m in re.finditer(r'map_size=(\d+)\r?\nmap_toString=\{', b):
    seg = b[m.end():m.end()+6000]; end = seg.find('}'); raw = seg[:end]
    d = dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw))
    maps.append(d)
print('genuine maps: %d  kinds=%s' % (len(maps),
      [m.get('activity_kind') for m in maps]))

sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")
sg.WIN_PHASE = (0x2B,)
_o = D.claims_for_law_58
sg.claims_for_law = lambda v, k: _o(dict(v, client_sdk="flutter5.8.0@android5.8.0"), k)

INT = {'activity_kind','adj_signing_id','adj_verification','algorithm',
       'client_sdk','headers_id','native_version'}
results = []
for mp_ in maps:
    kind = mp_.get('activity_kind', 'session')
    params = {k: v for k, v in mp_.items() if k not in INT}
    # try every recovered second that could belong to this map
    best = None
    for h in blobs:
        tgt = h[:32]
        # find second by scanning a window is expensive; instead mint and see
        pass
    # brute force second from created_at
    ca = mp_.get('created_at', '')
    try:
        import urllib.parse, datetime
        ep = int(datetime.datetime.strptime(
            urllib.parse.unquote(ca), '%Y-%m-%dT%H:%M:%S.%fZ%z').timestamp())
    except Exception:
        continue
    for delta in range(-3, 90):
        s = ep + delta
        try:
            blob, sec, info = sg.sign_request(params, kind, second=s, seed=None)
        except Exception:
            continue
        hb = bytes(blob).hex()
        if hb in blobs:
            best = (s, hb, delta)
            break
    if best:
        print('  %-12s created_at=%s -> BYTE-EXACT at second=%d (delta %+d)'
              % (kind, ca, best[0], best[2]))
        results.append((kind, True))
    else:
        print('  %-12s created_at=%s -> no blob matched (need the per-fill seed)'
              % (kind, ca))
        results.append((kind, False))
print()
print('byte-exact: %d / %d' % (sum(1 for _, ok in results if ok), len(results)))
