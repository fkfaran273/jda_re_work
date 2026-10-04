import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import adj9_signer as S

# usage: python sweep_v.py START_MS END_MS [WORKERS]
lo_ms, hi_ms = int(sys.argv[1]), int(sys.argv[2])
WORKERS = int(sys.argv[3]) if len(sys.argv) > 3 else 4

d = json.load(open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 '..', 'rev', 'saz_blobs.json')))
u = [x for x in d['units'] if x['activity_kind'] == 'attribution'][0]
p, sec = u['params'], u['signing_second']
val = S.claims_from_wire(p, 'attribution')
gold_body = u['body_hex']
gold_hdr = u['header_hex']

C, E = int(p['created_at'][20:23]), int(p['sent_at'][20:23])
lo_ms = max(lo_ms, C); hi_ms = min(hi_ms, E)

def one(ms):
    V = S.make_V(sec, ms * 1000)
    blob, info = S.mint_blob(val, 'attribution', second=sec, V=V)
    return ms, V, blob[:16].hex() == gold_hdr, blob[16:].hex() == gold_body

if __name__ == '__main__':
    import multiprocessing as mp
    found = []
    with mp.Pool(WORKERS) as pool:
        for ms, V, hdr, match in pool.imap_unordered(one, range(lo_ms, hi_ms + 1)):
            print('ms=%3d V=%08x hdr=%s body=%s' % (ms, V, 'OK' if hdr else 'NO',
                  'MATCH' if match else 'no'), flush=True)
            if match:
                found.append((ms, V))
                print('*** V SOLVED at ms=%d V=%08x ***' % (ms, V), flush=True)
    print('RANGE %d-%d done; matches=%s' % (lo_ms, hi_ms, found), flush=True)
