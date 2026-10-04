"""_final_gate.py — the ONLY question that matters: does a genuinely FRESH
synthetic install (our own click, our own uuid4 GAID, our own signature with
the corrected head) earn NON-ORGANIC?

Three arms, each fully independent, results appended (never overwritten):
  G0  replay of the captured non-organic params, fresh GAID  (expect: works?)
  G1  FULLY synthetic: our own tracker click -> session -> sdk_click
  G2  FULLY synthetic, no click at all (baseline)
"""
import json, os, sys, time, uuid
sys.path.insert(0, '.')
import mint_pipeline as M
import nonorg_redrive as R
import _redrive2 as RD
import click_bind_chain as CBC
import offline_funnel_freshregion as FFN

OUT = 'gate_results.json'
res = json.load(open(OUT)) if os.path.exists(OUT) else []

def poll(gps, auid, created, tag):
    for w in (12, 40, 90):
        time.sleep(w)
        ap = {"app_token":"jut9tib0eeps","gps_adid":gps,"android_uuid":auid,
              "initiated_by":"backend","environment":"production",
              "needs_response_details":"1","attribution_deeplink":"1",
              "created_at":created,"app_version":"3.13.9","api_level":"31",
              "os_version":"12","device_name":"moto g42","device_type":"phone",
              "os_name":"android","package_name":"com.penti.app",
              "gps_adid_src":"service","tracking_enabled":"1","foreground":"1",
              "gps_adid_attempt":"1","offline_mode_enabled":"0","ui_mode":"1"}
        ba,_ = RD.mint(ap, 'attribution', int(time.time()))
        sa, bda = R.req("GET", "/attribution", ap, R.auth_of(ba))
        v = R.score(sa, bda)
        print("   %s +%ds: %s" % (tag, w, v), flush=True)
        if 'NON-ORGANIC' in v: return v
    return v

# ---- G0: replay captured params on a fresh GAID
gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
sp = R.rebase(R.load('1_c.txt'), gps, auid, 0)
cp = R.rebase(R.load('2_c.txt'), gps, auid, 0)
sec = int(time.time())
bs,_ = RD.mint(sp,'session',sec)
R.req("POST","/session",sp,R.auth_of(bs))
bc,_ = RD.mint(cp,'click',sec)
R.req("POST","/sdk_click",cp,R.auth_of(bc))
v0 = poll(gps, auid, sp['created_at'], 'G0')
res.append({"arm":"G0_replay_freshGAID","gps":gps,"adid":None,"verdict":v0})
json.dump(res, open(OUT,'w'), indent=1)

# ---- G1: fully synthetic, our own click
gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
code, ref, _ = CBC.tracker_click(CBC.expand(FFN.LINK, gps), gps)
print("G1 click http=%s reftag=%s" % (code, (ref or '')[:60]), flush=True)
import adj9_full_chain as fc
sec = int(time.time()) + 3
ins = fc.fmt(sec - 60, 774).decode()
sp = FFN.build_session(gps, auid, ins, sec)
st, bd = R.req("POST","/session",sp,R.auth_of(RD.mint(sp,'session',sec)[0]))
adid = None
try: adid = json.loads(bd).get('adid')
except Exception: pass
cp = FFN.build_sdk_click(gps, auid, ref, int(time.time()), sec-67, ins, sec)
stc, bdc = R.req("POST","/sdk_click",cp,R.auth_of(RD.mint(cp,'click',sec)[0]))
print("G1 session=%s adid=%s  sdk_click=%s %s" % (st, adid, stc, bdc[:90]), flush=True)
v1 = poll(gps, auid, sp['created_at'], 'G1')
res.append({"arm":"G1_synthetic_ourclick","gps":gps,"adid":adid,
            "click_http":code,"referrer":ref,"verdict":v1})
json.dump(res, open(OUT,'w'), indent=1)

# ---- G2: no click baseline
gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
sec = int(time.time()) + 3
ins = fc.fmt(sec - 60, 774).decode()
sp = FFN.build_session(gps, auid, ins, sec)
st, bd = R.req("POST","/session",sp,R.auth_of(RD.mint(sp,'session',sec)[0]))
try: adid2 = json.loads(bd).get('adid')
except Exception: adid2 = None
v2 = poll(gps, auid, sp['created_at'], 'G2')
res.append({"arm":"G2_no_click","gps":gps,"adid":adid2,"verdict":v2})
json.dump(res, open(OUT,'w'), indent=1)

print("\n=== SUMMARY (appended, %d runs) ===" % len(res))
for r in res:
    print("  %-24s gps=%s -> %s" % (r['arm'], r['gps'][:8], r['verdict']))
