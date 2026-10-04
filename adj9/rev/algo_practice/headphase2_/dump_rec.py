import os, sys, struct
REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR, emu_8d6f4 as E, adj9_pure as AP

cfg = FR.build_cfg(0)
cfg["urandom8"] = bytes.fromhex("11223344")
e = E.Emu(cfg=cfg)
st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
print("stopped", st)
print("result keys", list(e.result.keys()))
blob = e.result.get("blob") or b""
print("blob len", len(blob))
print("blob hex:", blob.hex(" "))
if len(blob) >= 160:
    rec = AP.whiten_body_inverse(blob[16:160], blob[:16])
    print("rec hex:", rec.hex(" "))
    print("rec[0:3]", rec[0:3].hex(), "tag19", hex(rec[19]), "tag24", hex(rec[24]),
          "tag45", hex(rec[45]), "tag78", hex(rec[78]), "tag111", hex(rec[111]))
    print("seed@20", rec[20:24].hex())
print("header law check:", AP.make_header(int(cfg["time_sec"])).hex(), "vs", blob[:16].hex())
