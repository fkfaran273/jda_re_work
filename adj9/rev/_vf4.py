import base64, struct, sys
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod
import whiten_decoder as WD
gen = base64.b64decode(open('transport_blob.txt').read().strip())
d = WD.decode_blob(gen)
S = d['F_seed']; target = d['head']
print('F_seed = 0x%08x   genuine head = %s' % (S, target.hex()))
print()
cands = [('(0x2b,)', (0x2b,)), ('(0x2b,0x48)', (0x2b, 0x48)),
         ('(0x2b,0x41)', (0x2b, 0x41)), ('(0x2b,0x22)', (0x2b, 0x22)),
         ('(0x2b,0x22,0x25,0x2e)', (0x2b, 0x22, 0x25, 0x2e)),
         ('HEAD_FIRST', Fmod.HEAD_FIRST), ('HEAD_RESIGN', Fmod.HEAD_RESIGN)]
for nm, head in cands:
    d0w, _, _ = Fmod.region(S, M.DEFAULT_PID, 0, head=head)
    # record stores head as rev16'd words, LE-packed
    hw = b''.join(struct.pack('>I', w ^ 0xFFFFFFFF)[::-1] for w in d0w[:4])
    print('  %-20s %s  %s' % (nm, hw.hex(), '*** MATCH ***' if hw == target else ''))
