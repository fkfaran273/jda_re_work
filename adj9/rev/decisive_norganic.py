# decisive_norganic.py — THE decisive test (slice 97 §5.3):
# 1) farm_win procedure: fresh GAID + tracker click (marker creative) →
#    wipe state + relaunch (NOT pm clear: keep the sig-SDK classes loaded)
#    → the app signs the install burst.
# 2) Attach pre-guard BEFORE relaunch; piggy-mint activity_kind=attribution
#    (fresh stamps, our map) inside that burst.
# 3) Send the minted blob from PC (send_auth) + bracket: the app's own
#    captured nsign blob verbatim.
# 4) Read the device's own AdjustAttribution verdict as ground truth.
# Usage: python decisive_norganic.py
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import farm_win as fw
import sig_probe as sp
import frida

OUT = os.path.join(HERE, "decisive_result.json")
AGENT = os.path.join(HERE, "agent", "adj9agent.js")


def attach_pre_guard():
    """pidof the app, force-stop, attach pre-guard, relaunch — like mint4_run."""
    pid = fw.sh("pidof com.penti.app").strip()
    if pid:
        fw.sh("am force-stop com.penti.app")
        time.sleep(1)
    pid = fw.sh("pidof com.penti.app").strip()
    if not pid:
        pid = fw.sh("monkey -p com.penti.app 1; pidof com.penti.app").strip()
    dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    scr = dev.attach(int(pid.split()[0]))
    scr.on("message", lambda m, d: print("[ev]", str(m.get("payload"))[:150],
                                        flush=True))
    scr.load()
    src = open(AGENT, encoding="utf-8").read()
    scr.create_script(src) if False else None
    script = dev.create_script(src) if False else scr  # placeholder guard
    return scr


def main():
    # --- 1) farm procedure -------------------------------------------------
    gps = str(uuid.uuid4())
    creative = "cline_dec"
    fw.sh("adb forward tcp:27042 tcp:27042") if False else None
    got = fw.set_gaid(gps)
    print("GAID -> %s (readback %s)" % (gps, got), flush=True)
    code, ref, hops, url = fw.fire_click(gps, creative)
    print("click http=%s reftag=%s" % (code, (ref or "").split("&")[0]),
          flush=True)
    # --- 2) pre-guard attach + wipe/relaunch -------------------------------
    dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
    pid = fw.sh("pidof com.penti.app").strip() or "0"
    if pid != "0":
        fw.sh("am force-stop com.penti.app")
        time.sleep(1)
        pid = fw.sh("pidof com.penti.app").strip() or "0"
    scr = None
    if pid != "0":
        scr = dev.attach(int(pid))
        src = open(AGENT, encoding="utf-8").read()
        script = scr.create_script(src)
        script.on("message", lambda m, d: print("[ev]",
                    str(m.get("payload"))[:120], flush=True))
        script.load()
        time.sleep(1)
    else:
        print("app not running; launching once to get a pid", flush=True)
        fw.sh("monkey -p com.penti.app 1")
        time.sleep(6)
        pid = fw.sh("pidof com.penti.app").strip()
        scr = dev.attach(int(pid))
        src = open(AGENT, encoding="utf-8").read()
        script = scr.create_script(src)
        script.on("message", lambda m, d: print("[ev]",
                    str(m.get("payload"))[:120], flush=True))
        script.load()
        time.sleep(1)
    ev = {"piggy": None, "sigmap": None}
    script.on("message", lambda m, d: _on(m, ev))
    fw.wipe_relaunch()
    piggy = None
    for k in range(8):
        time.sleep(5)
        try:
            piggy = script.exports_sync.piggy_result()
        except Exception as e:
            print("piggy poll err %s" % e, flush=True)
        if piggy and piggy.get("ok"):
            break
    print("piggy: ok=%s blobLen=%s" % (piggy and piggy.get("ok"),
                                       piggy and piggy.get("blobLen")),
          flush=True)
    json.dump(piggy, open(os.path.join(HERE, "minted5.json"), "w"), indent=1)
    if not (piggy and piggy.get("ok")):
        print("NO PIGGY MINT — abort", flush=True)
        return
    # --- 3) send from PC ----------------------------------------------------
    blob = bytes.fromhex(piggy["blobHex"]) if "blobHex" in piggy else \
        base64.b64decode(piggy["blobB64"])
    auth = piggy["auth"]
    val = {}
    for k, v in piggy["mapPairs"]:
        val.setdefault(k, v)
    # reuse send_mint4's query builder
    import send_mint4 as sm
    sm.val, sm.blob, sm.auth = val, blob, auth
    url2 = "https://app.adjust.com/attribution?" + sm.qs(val)
    s, body = sm.send_auth(url2, blob, auth)
    v = sp.verdict(s, body)
    print("MINT send -> %s %s" % (s, v), flush=True)
    # bracket: the app's own nsign blob
    try:
        nb = base64.b64decode(piggy["nsignB64"])
        s2, body2 = sm.send_auth(url2, nb, piggy["nsignAuth"])
        print("NSIGN bracket -> %s %s" % (s2, sp.verdict(s2, body2)), flush=True)
    except Exception as e:
        print("bracket err %s" % e, flush=True)
    # --- 4) device ground truth ---------------------------------------------
    a, app_ref = {}, ""
    for k in range(5):
        time.sleep(10)
        a, app_ref = fw.read_verdict()
        if a:
            break
    print("DEVICE verdict: token=%s network=%s creative=%s"
          % (a.get("tracker_token"), a.get("network"), a.get("creative")),
          flush=True)
    ok = bool(a) and a.get("network") not in (None, "Organic")
    print("-> %s" % ("NON-ORGANIC JOINED" if ok else "Organic"), flush=True)
    json.dump({"gps": gps, "creative": creative, "click_http": code,
               "referrer": ref, "piggy": piggy, "send": [s, v],
               "device_verdict": a, "non_organic": ok},
              open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()
