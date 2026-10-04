import sys, os, struct, json
HERE=os.path.dirname(os.path.abspath(__file__)); TOOL=os.path.dirname(HERE); DEV=os.path.join(TOOL,'..','device'); REV=os.path.join(TOOL,'..','rev')
sys.path.insert(0,TOOL)
import adj9_signer as A

def wb(words): return b"".join(w.to_bytes(4,"big") for w in words)
def cap0(hx):
    b=bytes.fromhex(hx); return [int.from_bytes(b[i:i+4],"big") for i in range(0,len(b),4)]
def cap4(hx):
    b=bytes.fromhex(hx); return [int.from_bytes(b[i:i+4],"big") for i in range(0,len(b),4)]

print("=== region_laws on REAL captured d0 (all_signings EMIT rows) ===")
rows=json.load(open(os.path.join(REV,"all_signings.json"),encoding="utf-8"))
for idx,r in enumerate(rows[:10]):
    d0=cap0(r["d0"]); d4=cap4(r["d4"])
    L=A.region_laws(wb(d0),wb(d4))
    print(" row %2d: L1=%s L2=%s L3=%s  (d0[0]=%08x d0[1]=%08x)" % (idx, L["L1_tile_Rrep"],L["L2_d4_6_hi_eq_R"],L["L3_X_eq_U3"],d0[0],d0[1]))

print()
print("=== region_laws on REAL captured d0 (device/rows_full.json) ===")
rf=json.load(open(os.path.join(DEV,"rows_full.json"),encoding="utf-8"))["rows"]
for idx,r in enumerate(rf):
    d0=cap0(r["desc"]["0"]["hex"]); d4=cap4(r["desc"]["4"]["hex"])
    L=A.region_laws(wb(d0),wb(d4))
    print(" row %d sign_id=%s: L1=%s L2=%s L3=%s  (d0[0]=%08x d0[1]=%08x)" % (idx,r.get("sign_id"),L["L1_tile_Rrep"],L["L2_d4_6_hi_eq_R"],L["L3_X_eq_U3"],d0[0],d0[1]))

print()
print("=== region_laws on MODEL region() output (corrected heads) for those seeds ===")
# TRUE heads
for idx,r in enumerate(rf):
    seed=int.from_bytes(bytes.fromhex(r["desc"]["2"]["hex"]),"little")
    head=A.head_for_sign_id(r.get("sign_id",1))
    d0,d2,d4=A.region(seed,0,head=head)
    L=A.region_laws(wb(d0),wb(d4))
    print(" rows_full row %d (model head): L1=%s L2=%s L3=%s" % (idx,L["L1_tile_Rrep"],L["L2_d4_6_hi_eq_R"],L["L3_X_eq_U3"]))
