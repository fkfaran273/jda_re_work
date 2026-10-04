import sys, os, struct, json, importlib.util
HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
REV = os.path.join(TOOL, '..', 'rev')
sys.path.insert(0, TOOL)
import adj9_signer as A

# load F.py as a module
spec = importlib.util.spec_from_file_location("Fmod", os.path.join(REV, "F.py"))
F = importlib.util.module_from_spec(spec); spec.loader.exec_module(F)

rows = json.load(open(os.path.join(REV, "all_signings.json"), encoding="utf-8"))

def words(hx): 
    b=bytes.fromhex(hx); return [int.from_bytes(b[i:i+4],'big') for i in range(0,len(b),4)]

print("Testing each model against CAPTURED d0/d2/d4 (real EMIT traces). Seed recovered from captured d2 (byteswap).")
print()
okA=okF=0
for idx,r in enumerate(rows[:10]):
    d2w = int(r["d2"],16)
    seed = ((d2w & 0xff)<<24)|((d2w>>8&0xff)<<16)|((d2w>>16&0xff)<<8)|(d2w>>24&0xff)  # byteswap
    want_d0 = words(r["d0"])[:6]
    want_d4 = words(r["d4"])
    # model A: adj9_signer
    a_d0,a_d2,a_d4 = A.region(seed, 0)
    # model F
    f_d0,f_d2,f_d4 = F.region(seed, 0, 0)
    a_match = list(a_d0[:6])==want_d0 and list(a_d4)==want_d4
    f_match_first = list(f_d0[:6])==want_d0
    f_match = f_match_first and list(f_d4)==want_d4
    okA += a_match; okF += f_match
    print("row %d seed=%08x" % (idx, seed))
    print("   want d0[:6] =", " ".join("%08x"%x for x in want_d0))
    print("   A    d0[:6] =", " ".join("%08x"%x for x in a_d0[:6]), "d4match=%s"%(list(a_d4)==want_d4))
    print("   F    d0[:6] =", " ".join("%08x"%x for x in f_d0[:6]), "d4match=%s"%(list(f_d4)==want_d4))
    print("   A first6 match=%s  F first6 match=%s  F full match=%s" % (a_match, f_match_first, f_match))
    print()
print("A(adj9_signer) full-region match: %d/%d" % (okA, len(rows[:10])))
print("F full-region match: %d/%d" % (okF, len(rows[:10])))
