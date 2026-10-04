"""_verify192b.py — full independent verification of the 192/192 claim."""
import base64, binascii, struct, sys
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod
import whiten_decoder as WD

gen = base64.b64decode(open('transport_blob.txt').read().strip())
rec = WD.decode_blob(gen)
print('decoded record len:', len(rec) if rec else None)
if rec:
    print('magic   :', rec[0:3].hex())
    print('head    :', rec[3:19].hex(), ' <- d0[0..3]')
    print('S (BE32):', rec[20:24].hex())
    S = int.from_bytes(rec[20:24], 'big')
    print()
    print('S = 0x%08x' % S)
    # now find which head phase reproduces the genuine head bytes
    for nm, head in (('(0x2b,)', (0x2b,)), ('(0x2b,0x48)', (0x2b, 0x48)),
                     ('HEAD_FIRST', Fmod.HEAD_FIRST),
                     ('HEAD_RESIGN', Fmod.HEAD_RESIGN)):
        d0w, d2w, d4w = Fmod.region(S, M.DEFAULT_PID, 0, head=head)
        d0 = b''.join(w.to_bytes(4,'big') for w in d0w)
        # the record stores head words rev16'd, LE-packed
        hw = b''.join(struct.pack('>I', w ^ 0xFFFFFFFF) [::-1] for w in d0w[:4])
        print('  %-12s head=%s %s' % (nm, hw.hex(), 'MATCH' if hw == rec[3:19] else ''))
