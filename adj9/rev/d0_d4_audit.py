# d0_d4_audit.py - deep dive on d0 and d4 structure
import json, struct, hashlib
from header_gen import Random3, make_header

ALL = json.load(open('all_signings.json', encoding='utf-8'))

print("=" * 70)
print("DEEP DIVE: d0 and d4 structure analysis")
print("=" * 70)

print("\n=== d0 Structure ===")
print("(144 bytes = 8-byte tile repeated 18 times)")

for i, s in enumerate(ALL):
    d0 = bytes.fromhex(s['d0'])
    d2 = int(s['d2'], 16)
    d8 = bytes.fromhex(s['d8'])
    d9 = bytes.fromhex(s['d9'])
    d10 = bytes.fromhex(s['d10'])
    d7 = struct.pack('>I', int(s['d7'], 16))
    
    tile = d0[:8]
    print(f"\n#{i}: d2={d2:#010x}")
    print(f"    d0 = tile({tile.hex()}) × 18")
    print(f"    tile as 2× uint32: {struct.unpack('>II', tile)}")
    
    # Check if tile might be related to anything
    # Try: is tile a counter/sequence number?
    # Try: is tile derived from d8 first 8 bytes XORed with something?
    d8_first8 = d8[:8]
    d9_first8 = d9[:8]
    
    print(f"    d8[:8] = {d8_first8.hex()}")
    print(f"    d9[:8] = {d9_first8.hex()}")
    print(f"    tile XOR d8[:8] = {(bytes(a^b for a,b in zip(tile, d8_first8))).hex()}")
    print(f"    tile XOR d9[:8] = {(bytes(a^b for a,b in zip(tile, d9_first8))).hex()}")
    
    # Try: is tile = d2 as little-endian?
    d2_le = struct.pack('<I', d2)
    d2_le_8 = d2_le + d2_le
    print(f"    d2 LE 8B = {d2_le_8.hex()} match={tile==d2_le_8}")
    
    # Try: is tile = d2 BE 8 bytes (d2 || d2)?
    d2_be_8 = struct.pack('>I', d2) + struct.pack('>I', d2)
    print(f"    d2 BE 8B = {d2_be_8.hex()} match={tile==d2_be_8}")

print("\n\n" + "=" * 70)
print("=== d4 Structure (32 bytes) ===")
print("=" * 70)

for i, s in enumerate(ALL):
    d2_bytes = struct.pack('>I', int(s['d2'], 16))
    d2 = int(s['d2'], 16)
    d4 = bytes.fromhex(s['d4'])
    d7 = struct.pack('>I', int(s['d7'], 16))
    d8 = bytes.fromhex(s['d8'])
    d9 = bytes.fromhex(s['d9'])
    d10 = bytes.fromhex(s['d10'])
    
    print(f"\n#{i}: d4={d4.hex()}")
    
    # d4 first 8 bytes might be a counter or hash prefix
    d4_first8 = d4[:8]
    d4_last8 = d4[-8:]
    
    # Test if d4 first 8 bytes = anything we know
    tests = [
        ('d2 BE 8B', struct.pack('>I', d2) + struct.pack('>I', d2)),
        ('d2 LE 8B', struct.pack('<I', d2) + struct.pack('<I', d2)),
        ('d7', d7),
        ('d7 BE 8B', d7 + d7),
        ('d8[:8]', d8[:8]),
        ('d9[:8]', d9[:8]),
        ('d10[:8]', d10[:8]),
    ]
    
    for name, val in tests:
        if val == d4_first8:
            print(f"    d4[:8] MATCHES {name}")
        elif val == d4_last8:
            print(f"    d4[-8:] MATCHES {name}")
    
    # Try possible HMAC keys
    possible_keys = [
        ('d8', d8),
        ('d9', d9),
        ('d8+d9', d8 + d9),
        ('d9+d8', d9 + d8),
    ]
    
    for key_name, key in possible_keys:
        # HMAC-SHA256 with key and d2+d7+d10 as message
        import hmac
        msg = d2_bytes + d7 + d10
        mac = hmac.new(key, msg, hashlib.sha256).digest()
        if mac == d4:
            print(f"    MATCH: HMAC-SHA256(key={key_name}, msg=d2+d7+d10)")
        elif mac[:16] == d4[:16]:
            print(f"    PARTIAL: HMAC-SHA256({key_name})[:16]")
        
        # Try with just d10 as message
        mac = hmac.new(key, d10, hashlib.sha256).digest()
        if mac == d4:
            print(f"    MATCH: HMAC-SHA256(key={key_name}, msg=d10)")
        
        # Try with d2+d7
        mac = hmac.new(key, d2_bytes + d7, hashlib.sha256).digest()
        if mac == d4:
            print(f"    MATCH: HMAC-SHA256(key={key_name}, msg=d2+d7)")

print("\n" + "=" * 70)
print("=== Searching for APK-embedded secrets ===")
print("=" * 70)
print("""
If d0 and d4 require a secret, it must be in the APK or derived from the APK.
Possible locations:
1. cert/tapZX-dex-2.dex - the .dex files in the APK
2. resources.arsc - resources
3. Embedded as string constant in classes.dex
4. Generated at runtime from APK signature/certificate

The d8 and d9 values are constant - these MIGHT be:
- d8: A key or key identifier
- d9: A certificate fingerprint or signature

Let me search the codebase for where d8/d9 values appear.
""")

# Search for d8/d9 values in code
d8_hex = list(set(s['d8'] for s in ALL))[0]
d9_hex = list(set(s['d9'] for s in ALL))[0]

print(f"\nd8 constant value: {d8_hex}")
print(f"d9 constant value: {d9_hex}")
print(f"\nSearching for these values in the codebase...")
