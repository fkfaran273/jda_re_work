# sign_analysis.py - analyze all 10 captured signings from all_signings.json
import json, struct

ALL = json.load(open('all_signings.json', encoding='utf-8'))
FIN = json.load(open('fin_descs.json', encoding='utf-8'))

print("=== All 10 captured signings ===\n")
for i, s in enumerate(ALL):
    d2 = int(s['d2'], 16)
    d7 = s['d7']
    d8_short = s['d8'][:32]
    d9_short = s['d9'][:32]
    d0 = bytes.fromhex(s['d0'])
    d4 = bytes.fromhex(s['d4'])
    d10 = bytes.fromhex(s['d10'])
    print(f"#{i}: sec={d2:#010x} d7={d7}  d8={d8_short}  d9={d9_short}")
    print(f"     d0 tile: {d0[:8].hex()}  (len={len(d0)})")
    print(f"     d4: {d4.hex()}")
    print(f"     d10 first 48B: {d10[:48].hex()}")
    print()

print("=== Constancy check ===")
d2_vals = {s['d2'] for s in ALL}
d7_vals = sorted({s['d7'] for s in ALL})
d8_vals = {s['d8'] for s in ALL}
d9_vals = {s['d9'] for s in ALL}
print(f"d2 distinct values: {len(d2_vals)} (seconds vary per signing)")
print(f"d7 distinct values: {d7_vals}")
print(f"d8 distinct: {len(d8_vals)} -> {list(d8_vals)[0][:32] if len(d8_vals)==1 else 'MULTIPLE'}")
print(f"d9 distinct: {len(d9_vals)} -> {list(d9_vals)[0][:32] if len(d9_vals)==1 else 'MULTIPLE'}")
print()

print("=== d0 tile analysis ===")
for i, s in enumerate(ALL):
    d0 = bytes.fromhex(s['d0'])
    tile = d0[:8]
    nrep = len(d0) // 8
    ok = all(d0[j*8:j*8+8] == tile for j in range(nrep))
    print(f"#{i}: len={len(d0)}B tile={tile.hex()} reps={nrep} consistent={ok}")
print()

print("=== d4 analysis (potential signature/mask value) ===")
for i, s in enumerate(ALL):
    d4 = bytes.fromhex(s['d4'])
    print(f"#{i}: d4={d4.hex()} (len={len(d4)})")
print(f"d4 distinct: {len({s['d4'] for s in ALL})} of {len(ALL)}")
