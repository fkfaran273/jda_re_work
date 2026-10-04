"""_lawchk.py — the corrected head must pass L1/L2/L3, and the live mint must
still be exit-clean 192 B with the header law intact."""
import sys, time
sys.path.insert(0, '.')
import mint_pipeline as MP
import F as Fmod
import offline_funnel_freshregion as FFN

sec = int(time.time()) - 5
V = MP.make_V_consistent(sec, 928)
d0w, d2w, d4w = Fmod.region(V, MP.DEFAULT_PID, 0, head=MP.DEVICE_SELECTORS)
import struct
d0 = b''.join(w.to_bytes(4,'big') for w in d0w)
d4 = b''.join(w.to_bytes(4,'big') for w in d4w)
laws = MP.region_laws(d0, d4)
print('region_laws with corrected head:', laws)
print('DEVICE_SELECTORS =', tuple(hex(x) for x in MP.DEVICE_SELECTORS))
print('head_for_endpoint(session) =', tuple(hex(x) for x in MP.head_for_endpoint('session')))
print()
# live-shaped mint through the funnel
ins = None
import adj9_full_chain as fc
ins = fc.fmt(sec - 170, 774).decode()
p = FFN.build_session('GPS','AUID', ins, sec)
blob, info = FFN.mint_signed('session', p, sec)
print('funnel session mint: len=%d status=%s' % (len(blob), info['status']))
print('header law intact  :', blob[:16] == MP.make_header(sec))
print('n_claims=%d desc10=%d' % (info['n_claims'], info['desc10_len']))
