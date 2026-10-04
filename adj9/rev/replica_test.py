#!/usr/bin/env python3
"""replica_test.py — user-model test, replica configuration.
Theory under test: 'server cannot know key2; it verifies what it can recompute
and/or books+matches packages. Our funnels always shipped FAKE inputs
(HRAND=random H, ZERO0=#0) -> that is the missing mismatch.'
Arm R (replica): make_signature with HRAND=False AND ZERO0=False -> the blob
reuses the CAPTURED device H, #0 tile, #2, #8 verbatim; only gps/auid/created
claims are swapped to the fresh clicked identity. Header = proven Random3 law.
Arm S (control): current funnel defaults (HRAND=True, ZERO0=True).
Prediction: under the user model, R joins the click engagement -> non-organic;
S stays Organic (as every funnel so far).
"""
import base64, json, os, sys, time, uuid
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj9_full_chain as F
from farm_win import fire_click

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
OUT = os.path.join(HERE, "replica_result.json")
LINK = "https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic&click_id={click_id}&idfa={sub3}&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp&event_callback_bfi71x=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp"

F.MINT_SKEW = -2
F.OFF_MINUTES, F.OFF_LABEL = 330, "+0530"
F.USE_PROXY = True            # direct egress to app.adjust.com hangs from this PC
F.DEV = dict(F.DEV)           # moto profile (matches captured material)

res = {"when": time.strftime("%Y-%m-%d %H:%M:%S"), "arms": {}}

def attr_body(r):
    try:
        a = json.loads(r)["attribution"]
        return "%s|%s|eng=%s" % (a.get("tracker_token"), a.get("network"),
                                 a.get("engagement_time"))
    except Exception:
        return "unparsed:" + r[:160]

def run_arm(name, replica):
    F.HRAND = not replica       # replica: keep captured H
    F.ZERO0 = not replica       # replica: keep captured #0 tile
    gps, auid = str(uuid.uuid4()), str(uuid.uuid4())
    creative = ("rep_" if replica else "ctl_") + uuid.uuid4().hex[:4]
    print(f"=== ARM {name}: gps={gps} auid={auid} creative={creative} "
          f"HRAND={F.HRAND} ZERO0={F.ZERO0}")
    code, ref, _hops, _url = fire_click(gps, creative, LINK,
                                        use_idfa=True, use_gps=True)
    print("   click ->", (ref or "NO-REF")[:110])
    t0 = time.time()
    created = F.fmt(int(t0), 123)
    st, steps, blob = F.make_signature(int(t0), created, gps=gps, auid=auid)
    print(f"   minted st={st} steps={steps} "
          f"b64[:24]={base64.b64encode(blob).decode()[:24]}...")
    ins = F.fmt(int(t0 + 27), 431)
    s2, r2 = F.api_session(gps, auid, ins)
    print("   SESSION:", s2, r2[:150])
    time.sleep(5)
    s1, r1 = F.api_sdk_click(gps, auid, ref, int(t0), int(t0 + 20), ins)
    print("   SDK-CLICK:", s1, r1[:150])
    time.sleep(6)
    ptoken = "e" + uuid.uuid4().hex + ":APA91b" + uuid.uuid4().hex
    out = []
    for i in range(3):
        s3, r3 = F.api_attribution(gps, auid, ptoken, "sdk")
        verdict = attr_body(r3)
        out.append([s3, verdict])
        print(f"   ATTR#{i+1}: {s3} {verdict}")
        time.sleep(6)
    res["arms"][name] = {"gps": gps, "auid": auid, "creative": creative,
                         "session": [s2, r2[:200]], "click": [s1, r1[:200]],
                         "attrs": out}
    json.dump(res, open(OUT, "w"), indent=1)

print("replica test — R = captured H/#0/#2/#8 verbatim, S = funnel defaults")
run_arm("R_replica_captured_inputs", True)
time.sleep(10)
run_arm("S_control_fresh_inputs", False)
print("\n=== SUMMARY ===")
for k, v in res["arms"].items():
    print(k, "->", "; ".join(f"{s}:{b}" for s, b in v["attrs"]))
json.dump(res, open(OUT, "w"), indent=1)
print("saved", OUT)