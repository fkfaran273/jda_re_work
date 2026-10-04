import sys, os, json
HERE=os.path.dirname(os.path.abspath(__file__)); TOOL=os.path.dirname(HERE); REV=os.path.join(TOOL,'..','rev')
sys.path.insert(0,TOOL)
import adj9_signer as A
d=json.load(open(os.path.join(REV,"saz_blobs.json")))
for u in d["units"]:
    sec=u["signing_second"]
    hdr=A.make_header(sec).hex()
    print("kind=%-13s sec=%d  make_header=%s  gold=%s  match=%s" % (
        u["activity_kind"], sec, hdr, u["header_hex"], hdr==u["header_hex"]))
