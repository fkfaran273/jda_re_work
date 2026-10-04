"""_declic_head.py — recover the GENUINE declic d0 head phase."""
import re, sys
sys.path.insert(0, '.')
import adj9_signature as S

b = open('../adj9/rev/creditsea/adj9_cap_declic.log', 'rb').read().decode('utf-8', 'replace')
blobs = list(dict.fromkeys(re.findall(
    r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]{384})", b)))
print('genuine declic blobs:', len(blobs))
for h in blobs:
    d = S.decode_blob(bytes.fromhex(h))
    print()
    print('  F_seed  : %08x' % d['F_seed'])
    print('  head    : %s' % d['head'].hex())
    print('  cert    : %s' % d['record'][25:45].hex())
    d4 = S._d4_words(d['F_seed'])
    hits = []
    for a in range(0x20, 0x60):
        if S.head_words(S._d0_words(d4, head=(a,))) == d['head']:
            hits.append([a])
    for a in range(0x20, 0x60):
        for c in range(0x20, 0x60):
            if S.head_words(S._d0_words(d4, head=(a, c))) == d['head']:
                hits.append([a, c])
    print('  HEAD PHASE: %s' % [tuple('0x%02x' % x for x in hh) for hh in hits])
