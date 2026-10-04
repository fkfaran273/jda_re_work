# desc10_scan.py - scan ALL 39673 EMIT dwords in whcap_hits7.json for desc10-shaped
# ASCII runs (start KlcAG2cb... = adj_verification), classify session vs click.
import json, struct, re

DEV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device'
d = json.load(open(DEV + r'\whcap_hits7.json', encoding='utf-8'))
evs = [e for e in d if e.get('tag') == 'emit']
print('emit events:', len(evs))

words = [int(e['val'], 16) for e in evs]
sinks = [e['sink'] for e in evs]

def ascii_run(start_dw):
    """decode a contiguous printable-ASCII byte run starting at dword start_dw"""
    out = bytearray()
    i = start_dw
    n = len(words)
    while i < n:
        b = struct.pack('>I', words[i])
        ok = all(32 <= c < 127 for c in b)
        if ok:
            out += b
            i += 1
        else:
            # allow the LAST dword of the run to be partially printable (padding)
            if out and any(32 <= c < 127 for c in b):
                # stop anyway; desc10 might end mid-dword in a later field
                break
            break
    return bytes(out)

# find all starts: 'KlcA' dword AND the next 6 dwords spell the adj_verification
TARGET28 = b'KlcAG2cbAAsKSl1KVi0FGiJbDHMI'
hits = []
for i in range(len(words) - 7):
    b = b''.join(struct.pack('>I', w) for w in words[i:i + 7])
    if b == TARGET28:
        hits.append(i)
print('desc10-head hits:', len(hits), 'at dword indices', hits[:20])

for i in hits:
    run = ascii_run(i)
    ak = 'click' if b'activity_kind' in run[-60:] and b'click' in run[-60:] else (
         'session' if b'session' in run[-60:] else '?')
    print('--- run @dw %d sink %s len %dB kind=%s' % (i, sinks[i][-6:], len(run), ak))
    print('   head:', run[:100])
    print('   tail:', run[-80:])
    # compare to golden desc10
    D = json.load(open(r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\fin_descs.json', encoding='utf-8'))
    g10 = bytes.fromhex([x for x in D['descs'] if x['build_idx'] == 10][0]['data_hex'])
    same = run[:len(g10)] == g10 and len(run) == len(g10)
    print('   == golden desc10:', same, '| kind byte cmp:', run[334:341])
