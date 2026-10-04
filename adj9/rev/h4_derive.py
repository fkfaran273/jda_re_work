# h4_derive.py - what IS descriptor #4, now that it is proven not to be H?
#
# Facts established (h_ident.py / h_ident2.py):
#   * the golden signing's H = wh4_records.mac_doFinal[7] = eebe704e53a5cd3d…ab56fb9b
#   * fin_descs[#4] = 00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e
#     -> #4 != H, and no H occurs anywhere in the 192-byte blob
#   * fin_descs.json's 11 descriptors reproduce the blob 48/48 with NO H present
#     => H is not an input to the blob computation
#
# So the maker's real unknowns are #0, #2 and #4. #4 is structured (not a MAC),
# which makes it a derivation candidate. This script runs a correlation battery
# between #4 and everything the wh4 session recorded for the same signing.
import base64
import hashlib
import json
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
R = json.load(open(os.path.join(HERE, 'wh4_records.json'), encoding='utf-8'))
FD = json.load(open(os.path.join(HERE, 'fin_descs.json'), encoding='utf-8'))
GI = R['golden_sign_input_idx']

def hbytes(v):
    """mac_doFinal entries are dicts like {'hex': '...'} (or list/str)."""
    if isinstance(v, dict):
        for k in ('hex', 'data_hex', 'value', 'bytes'):
            if k in v:
                return hbytes(v[k])
        raise ValueError('no hex field in %s' % list(v)[:5])
    if isinstance(v, list):
        return bytes(v)
    s = str(v).replace('0x', '').strip()
    return bytes.fromhex(s)


d4 = bytes.fromhex([d for d in FD['descs'] if d['build_idx'] == 4][0]['data_hex'])
H = hbytes(R['mac_doFinal'][GI])
blob = bytes.fromhex(FD['target']['blob_hex'])
second = FD['target']['second']

print('golden #4 = %s' % d4.hex())
print('golden H  = %s' % H.hex())
print('second    = %d' % second)
print()

si = R['sign_inputs']
canon = R['canonicals']
print('sign_inputs[%d] type=%s len=%s' % (GI, type(si[GI]).__name__,
                                          len(si[GI]) if hasattr(si[GI], '__len__') else '-'))
print('canonicals[%d]  type=%s len=%s' % (GI, type(canon[GI]).__name__,
                                          len(canon[GI]) if hasattr(canon[GI], '__len__') else '-'))


def asbytes(v):
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        return v.encode('utf-8', 'replace')
    if isinstance(v, list):
        return bytes(v)
    return str(v).encode()


SIG = asbytes(si[GI])
CAN = asbytes(canon[GI])
print()
print('sign_input bytes (%d): %s' % (len(SIG), SIG[:80]))
print('canonical  bytes (%d): %s' % (len(CAN), CAN[:80]))
print()

# ---- battery 1: is #4 (or its tail) a digest of the signing's own material? ----
print('=== battery 1: digest of own material (24-B tail / 32-B whole) ===')
msgs = {'sign_input': SIG, 'canonical': CAN, 'claims': None}
for d in FD['descs']:
    if d['build_idx'] == 10:
        msgs['claims'] = bytes.fromhex(d['data_hex'])
msgs['sign_input+claims'] = SIG + (msgs['claims'] or b'')
msgs['claims+sign_input'] = (msgs['claims'] or b'') + SIG
msgs['second_be'] = struct.pack('>I', second)
msgs['second_le'] = struct.pack('<I', second)
msgs['H'] = H
msgs['sign_input+H'] = SIG + H
msgs['H+sign_input'] = H + SIG

def digests(b):
    return {
        'md5': hashlib.md5(b).digest(),
        'sha1': hashlib.sha1(b).digest(),
        'sha256': hashlib.sha256(b).digest(),
        'sha512': hashlib.sha512(b).digest(),
        'sha256[:24]': hashlib.sha256(b).digest()[:24],
        'sha1[:24]': hashlib.sha1(b).digest()[:24],
        'sha256[:8]': hashlib.sha256(b).digest()[:8],
        'crc32': struct.pack('>I', zlib.crc32(b) & 0xffffffff),
        'crc32_le': struct.pack('<I', zlib.crc32(b) & 0xffffffff),
        'b64sha256_24': base64.b64encode(hashlib.sha256(b).digest())[:24],
    }

targets = {'whole #4': d4, '#4[0:8] head': d4[:8], '#4[8:32] tail': d4[8:],
           '#4 dwords BE->LE': b''.join(d4[i * 4:i * 4 + 4][::-1] for i in range(8))}
hits = 0
for mn, mb in msgs.items():
    if mb is None:
        continue
    for alg, dv in digests(mb).items():
        for tn, tv in targets.items():
            if dv and (tv.startswith(dv) or dv.startswith(tv) or tv == dv):
                print('  HIT  %s -> %s matches %s' % (mn, alg, tn))
                hits += 1
print('  digest hits: %d' % hits)
print()

# ---- battery 2: structure - plaintext fragments / pointer & length encodings ----
print('=== battery 2: plaintext / length / pointer structure ===')
for name, b in (('sign_input', SIG), ('canonical', CAN), ('claims', msgs['claims'])):
    if b and b[:8] in d4:
        print('  #4 contains first 8 bytes of %s' % name)
    if b and b[-8:] in d4:
        print('  #4 contains last 8 bytes of %s' % name)
lens = {'len(sign_input)': len(SIG), 'len(canonical)': len(CAN),
        'len(claims)': len(msgs['claims'] or b''), 'second': second}
dw = struct.unpack('>8I', d4)
for k, v in lens.items():
    for enc, bb in (('BE32', struct.pack('>I', v & 0xffffffff)),
                    ('LE32', struct.pack('<I', v & 0xffffffff))):
        if bb in d4:
            print('  %s (%d) appears in #4 as %s' % (k, v, enc))
print()
print('  #4 dwords (BE): %s' % [hex(x) for x in dw])
print('  per-dword popcount: %s' % [bin(x).count('1') for x in dw])
print('  total popcount: %d / 256 bits' % sum(bin(x).count('1') for x in dw))
print()

# ---- battery 3: is #4 invariant across the session (a context record)? ----
print('=== battery 3: repetition across the harvested corpus ===')
als = json.load(open(os.path.join(HERE, 'all_signings.json'), encoding='utf-8'))
vals = [s['d4'].lower() for s in als if s.get('d4')]
print('  distinct #4 values in all_signings: %d / %d' % (len(set(vals)), len(vals)))
heads = {}
for v in vals:
    heads.setdefault(v[:16], 0)
    heads[v[:16]] += 1
print('  distinct 8-byte heads: %d' % len(heads))
print('  heads: %s' % sorted(heads))
print()
print('  NOTE: if the head were a constant context id, heads would repeat;')
print('        %d distinct heads over %d samples means it is per-call.'
      % (len(heads), len(vals)))