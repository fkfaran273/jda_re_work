"""audit_claims.py — signed-claims vs wire cross-check (offline).

Patches FinEx to capture the exact descriptor bytes per mint, then asserts
every wire string that belongs in D10 is byte-present in the signed claims.
"""
import sys
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev')
import adj9_full_chain as F
from fin_vm2 import FinEx as RealEx

SEEN = {}
FAIL = []


class CapEx(RealEx):
    def __init__(self, seed, descs):
        SEEN['seed'] = seed
        SEEN['descs'] = [(l, t, bytes(b)) for (l, t, b) in descs]
        super().__init__(seed, descs)


F.FinEx = CapEx
CAP = {}
F.send = lambda u, p, b, method="POST": (CAP.update(
    last=(u, dict(p), b, method)), (200, '{"ok":1}'))[1]


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name
          + ((" :: " + str(detail)[:150]) if detail and not cond else ""),
          flush=True)
    if not cond:
        FAIL.append(name)


F.DEV, F.UA = dict(F.XIAOMI), F.XIAOMI_UA
F.OFF_MINUTES, F.OFF_LABEL = 120, "+0200"
F.ADD_IDFA = True
gps = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
auid = "11111111-2222-3333-4444-555555555555"
import io, contextlib
with contextlib.redirect_stdout(io.StringIO()):
    F.api_session(gps, auid, None)
url, p, blob, m = CAP['last']
d10 = None
for (l, t, b) in SEEN['descs']:
    if len(b) > 200:
        d10 = b
assert d10 is not None, "no claims blob captured"
print("D10 len:", len(d10), "claims #7 wine-views later", flush=True)
for key in ("gps_adid", "android_uuid", "created_at", "installed_at",
            "updated_at", "app_version", "device_name", "os_version",
            "api_level", "app_token"):
    v = p[key].encode()
    # os_version/api_level ride inside concatenations
    if key == "os_version":
        v = (p[key] + "com.penti.app").encode()
    if key == "api_level":
        v = (p[key] + "jut9tib0eeps").encode()
    check("claims contain wire " + key, v in d10, p[key])
check("claims contain adj_verification",
      b"KlcAG2cbAAsKSl1KVi0FGiJbDHMI" in d10)
# #7 == len(claims)?
for (l, t, b) in SEEN['descs']:
    pass
import struct
# find the 1-dw desc == len(d10)
lens = [(l, b.hex()) for (l, t, b) in SEEN['descs'] if l == 1]
print("1-dw descs:", lens, flush=True)
seven = [bytes.fromhex(h) for (l, h) in lens]
check("#7 == len(D10)", struct.pack(">I", len(d10)) in seven,
      [struct.unpack(">I", x)[0] for x in seven])
print("FAILURES:", FAIL if FAIL else "none", flush=True)
