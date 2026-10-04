"""d2_dep_analyze.py - quantitative analysis of d2/d4 probe deltas.

Tests, per body word i (blob words 4-47):
  affine law   word_i == A_i * d2 + C_i (mod 2^32)
    A_i  from the +1 probe add-delta
    ^2   predict add-delta == -2*A_i        (base bit1=1 -> newval = base-2)
    ^2^31 predict add-delta == (A_i&1)<<31  (base bit31=0 -> newval = base+2^31)
    d2=0  predict word == base - A_i*d2_base
    ffff  predict word == base - A_i*(d2_base+1)
  avalanche    hamming weight of each word's XOR delta (ideal 16/32)
Also: d4[4] halfword analysis (bit0 no-op vs bit16/bit31 full-body) and the
d2^1 vs d2+1 identity check.
"""
import json
import struct

M32 = 0xFFFFFFFF
res = json.load(open('d2_probe_result.json', encoding='utf-8'))
base = bytes.fromhex(res['base'])
bw = struct.unpack('>48I', base)
d2b = int(res['base_d2'], 16)
probes = {p['probe']: p for p in res['probes']}

def words(pname):
    return struct.unpack('>48I', bytes.fromhex(probes[pname]['blob']))

def deltas(pname):
    ww = words(pname)
    return [(i, ww[i] ^ bw[i], (ww[i] - bw[i]) & M32)
            for i in range(48) if ww[i] != bw[i]]

out = {'affine_law': {}, 'avalanche': {}, 'summary': {}}

# ---- 1. affine-law test on d2 ----
A = {}   # per-word multiplier from the +1 probe
for i, x, y in deltas('d2_plus1'):
    A[i] = y
w_xor2 = words('d2_xor2'); w_x31 = words('d2_xor80000000')
w_z = words('d2_zero');    w_f = words('d2_ffffffff')
pred2 = [((-2 * A.get(i, 0)) & M32) for i in range(48)]
pred31 = [((A.get(i, 0) & 1) << 31) for i in range(48)]
new2 = (d2b ^ 2) - d2b          # = -2
new31 = (d2b ^ 0x80000000) - d2b  # = +2^31
ok2 = ok31 = okz = okf = 0
nA = len(A)
for i in range(8, 48):
    a = A[i]
    if (w_xor2[i] - bw[i]) & M32 == (a * new2) & M32:
        ok2 += 1
    if (w_x31[i] - bw[i]) & M32 == (a * new31) & M32:
        ok31 += 1
    if w_z[i] == (bw[i] - a * d2b) & M32:
        okz += 1
    if w_f[i] == (bw[i] - a * (d2b + 1)) & M32:
        okf += 1
out['affine_law'] = {
    'model': 'word_i = A_i*d2 + C_i (mod 2^32), A_i from +1 probe',
    'n_body_words_dep': nA,
    'predict_xor2_add_delta': '%d/40' % ok2,
    'predict_xor2^31_add_delta': '%d/40' % ok31,
    'predict_d2_zero_word': '%d/40' % okz,
    'predict_d2_ffff_word': '%d/40' % okf,
    'affine_holds': ok2 == 40 and ok31 == 40 and okz == 40 and okf == 40,
}
print("AFFINE LAW:", json.dumps(out['affine_law']))

# ---- 2. avalanche stats ----
for pname in probes:
    mv = deltas(pname)
    if not mv:
        continue
    hw = [bin(x).count('1') for _, x, _ in mv]
    out['avalanche'][pname] = {
        'n_moved': len(mv), 'word_range': [mv[0][0], mv[-1][0]],
        'xor_hw_min': min(hw), 'xor_hw_max': max(hw),
        'xor_hw_mean': round(sum(hw) / len(hw), 1),
        'all_44_from_word4': mv[0][0] == 4,
        'all_40_from_word8': mv[0][0] == 8,
    }
    print("%-20s moved=%2d range=%s hw=%s" %
          (pname, len(mv), out['avalanche'][pname]['word_range'],
           out['avalanche'][pname]['xor_hw_mean']))

# ---- 3. d4[4]: is it consumed as high half only? ----
# bit0 flip -> 0 words; bit16 flip -> 44 words; bit31 flip -> 44 words.
# If word_i = f(hi16(d4[4])) the low half is invisible.  Check whether the
# two moving probes produce related outputs (no shared word values => both
# act through full mixing).
w4a = words('d4_4_xor80000000'); w4b = words('d4_4_xor00010000')
same = sum(1 for i in range(48) if w4a[i] == w4b[i])
out['summary']['d4_4_bit0'] = 'no-op (0/44 body words move)'
out['summary']['d4_4_bit16_bit31'] = 'full body (44 words, 4-47) move'
out['summary']['d4_4_lowhalf_invisible'] = True
out['summary']['d4_4_moving_probes_share_words'] = same
print("d4[4]: bit0 no-op; bit16/31 -> 44 words; shared words between the two"
      " moving probes:", same)

# ---- 4. d2^1 vs +1 identity (harness determinism check) ----
out['summary']['xor1_equals_plus1'] = res['xor1_equals_plus1']

# ---- 5. dependency map ----
dep = {
    'd2':  {'words': '8-47 (40 words)', 'words_4_7': 'no',
            'behavior': 'full avalanche: ANY single-bit or multi-bit change '
                        'moves all 40 words; xor hw ~16/32 (random-like)'},
    'd4_0': {'words': 'none', 'behavior': 'dead input: bit0/16/31 flips move '
             'nothing (also full-invert, prior dep_probe)'},
    'd4_4': {'words': '4-47 (44 words) via bits 16-31 only',
             'behavior': 'bit0 (low half) no-op; bit16 and bit31 flips move '
                         'the whole body incl. words 4-7'},
}
out['dependency_map'] = dep
json.dump(out, open('d2_probe_analysis.json', 'w'), indent=1)
print("saved d2_probe_analysis.json")
