# hypothesis_test.py - test if d0 and d4 are derivable from known inputs
import json, struct, hashlib
from header_gen import make_header, Random3

ALL = json.load(open('all_signings.json', encoding='utf-8'))

print("=== All 10 captured signings: d0 tile vs Random3(d2) ===\n")
for i, s in enumerate(ALL):
    d2 = int(s['d2'], 16)
    d0 = bytes.fromhex(s['d0'])
    tile = d0[:8]
    
    # Random3 is a class; make_header uses it internally
    R = Random3(d2)
    rnd3_first8 = struct.pack('>I', R.next()) + struct.pack('>I', R.next())
    mk_hdr = make_header(d2)
    mk_first8 = mk_hdr[:8]
    
    print(f"#{i}: d2={d2:#010x}")
    print(f"     d0 tile:    {tile.hex()}")
    print(f"     Random3[:8]: {rnd3_first8.hex()}  match={tile==rnd3_first8}")
    print(f"     make_hdr[:8]: {mk_first8.hex()}  match={tile==mk_first8}")
    print()

print("=== d4 analysis ===\n")
for i, s in enumerate(ALL):
    d2_bytes = struct.pack('>I', int(s['d2'], 16))
    d4 = bytes.fromhex(s['d4'])
    d7 = struct.pack('>I', int(s['d7'], 16))
    d8 = bytes.fromhex(s['d8'])
    d9 = bytes.fromhex(s['d9'])
    d10 = bytes.fromhex(s['d10'])
    
    print(f"#{i}: d4={d4.hex()}")
    
    candidates = [
        ('d2', d2_bytes),
        ('d7', d7),
        ('d8', d8),
        ('d9', d9),
        ('d10', d10),
        ('d2+d7', d2_bytes + d7),
        ('d8+d9', d8 + d9),
        ('d7+d8+d9', d7 + d8 + d9),
        ('d2+d7+d8+d9', d2_bytes + d7 + d8 + d9),
    ]
    
    for name, data in candidates:
        h = hashlib.sha256(data).digest()
        if h == d4:
            print(f"  MATCH: SHA256({name})")
        elif h[:8] == d4[:8]:
            print(f"  PARTIAL: SHA256({name})[:8] matches")
    print()
