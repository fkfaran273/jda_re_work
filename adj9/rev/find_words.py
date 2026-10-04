# find_words.py - where do the fresh #0 words / #2 / #4 come from? Search every
# device artifact (logs, json) for those 32-bit values (hex, both byte orders).
import json
import os
import struct

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
DEV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device'

TARGETS = {
    'S0_A_13271271': 0x13271271,
    'S0_B_db50f44c': 0xDB50F44C,
    'S0_B_b63798cc': 0xB63798CC,
    'S0_B_dab7f51a': 0xDAB7F51A,
    'S0_B_b7d0992b': 0xB7D0992B,
    'S1_A_aa447d3c': 0xAA447D3C,
    'S1_B_2ec65f51': 0x2EC65F51,
    'S1_B_efdf3cd8': 0xEFDF3CD8,
    'S2_A_f1a55b5b': 0xF1A55B5B,
    'S2_A_9949bda6': 0x9949BDA6,
    'S2_B_011d4d1e': 0x011D4D1E,
    'S2_B_13227bce': 0x13227BCE,
    'S2_B_21426d41': 0x21426D41,
    'S2_B_337d5f21': 0x337D5F21,
    'S0_H_00100400': 0x00100400,
    'S0_H_04144000': 0x04144000,
    'S0_2_fb1a8296': 0xFB1A8296,
    'S1_2_7c933329': 0x7C933329,
    'S2_2_4bce691e': 0x4BCE691E,
}

paths = []
for root in (DEV, REV):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('agent', 'node_modules')]
        for fn in filenames:
            if fn.lower().endswith(('.log', '.json', '.mlog', '.txt', '.md')):
                p = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(p) < 80 * 1024 * 1024:
                        paths.append(p)
                except OSError:
                    pass
print('files scanned:', len(paths))

found = {}
for p in paths:
    try:
        raw = open(p, 'rb').read()
    except OSError:
        continue
    for name, v in TARGETS.items():
        be = struct.pack('>I', v)
        le = struct.pack('<I', v)
        pats = [be.hex().encode(), le.hex().encode(),
                be.hex().upper().encode(), le.hex().upper().encode()]
        for pat in pats:
            if pat and pat in raw:
                found.setdefault(name, []).append(
                    '%s:%s' % (os.path.basename(p), pat.decode()))
                break

for name in TARGETS:
    print('  %-16s %s' % (name, '; '.join(found.get(name, []))[:150] or 'not found'))
json.dump(found, open(os.path.join(REV, 'find_words_result.json'), 'w'), indent=1)