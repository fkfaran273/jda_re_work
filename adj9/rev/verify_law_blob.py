# verify_law_blob.py - does the PROVEN recipe (test_h_swap.py control) reproduce
# the golden 192-B blob when descriptor #10/#7 are rebuilt from the desc10 LAW
# instead of taken from the capture? #4 (the VM's H input) stays captured.
import json
import os
import struct
import sys

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
sys.path.insert(0, REV)
from fin_vm2 import FinEx
from header_gen import make_header
import desc10_law as L

F = json.load(open(os.path.join(REV, 'fin_descs.json'), encoding='utf-8'))
W = json.load(open(os.path.join(REV, 'wh4_records.json'), encoding='utf-8'))
sec = F['target']['second']
want = bytes.fromhex(F['target']['blob_hex'])
D = [(d['build_idx'], d['len_dw'], bytes.fromhex(d['data_hex'])) for d in F['descs']]

si = W['sign_inputs'][W['golden_sign_input_idx']]
val = {}
for part in si['order'].split('\x02'):
    if '\x01' in part:
        k, v = part.split('\x01', 1)
        val[k] = v
law_d10 = L.build_desc10(val, 'session').encode('latin1')
print('law desc10 %d B | captured #10 %d B | equal: %s'
      % (len(law_d10), len(D[10][2]), law_d10 == D[10][2]))


def sig_from(descs):
    ex = FinEx(sec, [(lw, 0, dt) for (_, lw, dt) in descs])
    st = ex.run(max_steps=20_000_000)
    out = {}
    for (s, n, v) in ex.emit_trace:
        out[(s, n)] = v
    hdr = struct.unpack('>4I', make_header(sec))
    F0 = None
    for (s, n) in out:
        if tuple(out.get((s, k), 0) for k in range(4)) == hdr:
            F0 = s
            break
    if F0 is None:
        return st, None, None, len(out)
    sig = b''.join(struct.pack('>I', out.get((F0, k), 0)) for k in range(48))
    return st, sig, F0, len(out)


def cmp(tag, sig):
    if sig is None:
        print('%-26s NO STREAM with the header law' % tag)
        return False
    d = [i for i in range(192) if sig[i] != want[i]]
    print('%-26s %d B  %s%s' % (tag, len(sig),
                                'BYTE-EXACT' if not d else 'MISMATCH',
                                '' if not d else '  diffbytes=%d first@%d'
                                % (len(d), d[0])))
    return not d


# A) control: everything captured (file order == va_order) -> BYTE-EXACT
st, sig, F0, nev = sig_from(D)
print('control status=%s sink=%s events=%d' % (st, hex(F0) if F0 else F0, nev))
cmp('A captured #10 (control)', sig)

# B) rebuild descriptor #10 (build_idx 10) and #7 (build_idx 7) from the LAW,
#    selecting entries BY build_idx (not list position!)
Dlaw = []
for (bi, lw, dt) in D:
    if bi == 10:
        Dlaw.append((bi, len(law_d10) // 4, law_d10))
    elif bi == 7:
        Dlaw.append((bi, 1, struct.pack('>I', len(law_d10))))
    else:
        Dlaw.append((bi, lw, dt))
st, sig, F0, nev = sig_from(Dlaw)
print('law     status=%s sink=%s events=%d' % (st, hex(F0) if F0 else F0, nev))
cmp('B LAW-built #10/#7', sig)

# C) same as B but with a RANDOM #4 (the VM's H input) -> self-consistent but
#    different: proves #4 is an opaque input, everything else stays computable.
import secrets
Drand = [(bi, lw, (secrets.token_bytes(32) if bi == 4 else dt))
         for (bi, lw, dt) in Dlaw]
st, sig, F0, nev = sig_from(Drand)
print('randH4  status=%s sink=%s events=%d' % (st, hex(F0) if F0 else F0, nev))
cmp('C LAW #10 + random #4', sig)