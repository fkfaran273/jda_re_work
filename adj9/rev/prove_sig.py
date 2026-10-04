r"""prove_sig.py — the final A/B: SAME gps + SAME auid of a just-won NON-ORGANIC
install, answered twice: by a CRAFTED signature-maker poll and (if the wire tap
captured it) by the install's VERBATIM genuine blob.

Expected if slice 90's oracle holds:
  verbatim genuine  -> 400 {"ask_in":7200000}   BOOKED (server knows this request)
  crafted (maker)   -> 200 + Organic record     UNBOOKED (silent organic answer)
  genuine + 1 flip  -> 200 + Organic record     content-checked
...while the device's own AdjustAttribution holds the VKM non-organic verdict.

Usage: python prove_sig.py
"""
import base64
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as fc          # the signature maker (fin_vm2 + header_gen)
import sig_probe as sp                # send_raw / verdict helpers
import farm_win as fw                 # device readers (su_file)

fc.DEV, fc.UA = dict(fc.MOTO), fc.MOTO_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 330, "+0530"
DUMPS = r"D:\advance_emu\ssl_interception\wire_dumps"
OUT = os.path.join(HERE, "prove_sig_result.json")


def device_state():
    d = fw.su_file(fw.STATE)
    uids = re.findall(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
                      rb"[0-9a-f]{12}", d)
    auid = uids[0].decode() if uids else None
    d2 = fw.su_file(fw.ATTR)
    mt = re.search(rb"24[0-9a-z]{6}", d2)
    tok = mt.group(0).decode() if mt else None
    net = ("VKM Digital Yeni" if b"VKM Digital" in d2
           else "Organic" if b"Organic" in d2 else "?")
    if len(uids) > 1:
        print("note: %d uuids in state: %s" % (len(uids),
                                               [u.decode() for u in uids]))
    return auid, tok, net


def latest_capture(auid):
    """Newest captured /attribution request for this auid in the tap dump."""
    path = os.path.join(DUMPS, "app.adjust.com_dev2srv.bin")
    if not os.path.exists(path):
        print("no dump file:", path)
        return None, None
    mtime = os.path.getmtime(path)
    print("dump mtime: %s (%.1f min ago)"
          % (time.strftime("%H:%M:%S", time.localtime(mtime)),
             (time.time() - mtime) / 60))
    raw = open(path, "rb").read()
    blob = url = None
    for m in re.finditer(re.escape(auid.encode()), raw):
        seg = raw[max(0, m.start() - 6144): m.start() + 2048]
        mu = re.search(rb"GET (/\S*attribution\S*) HTTP", seg)
        mb = re.search(rb'Authorization: Signature signature="'
                       rb'([A-Za-z0-9+/=]{200,400})"', seg)
        if mu and mb:
            url = "https://app.adjust.com" + mu.group(1).decode()
            try:
                blob = base64.b64decode(mb.group(1))
            except Exception:
                blob = None
    return url, blob


def main():
    # Route through the validated local MITM proxy (clickIP == callIP == our
    # egress); direct egress to app.adjust.com hangs from this PC.
    import device_funnel as df
    df.install_proxy("http://127.0.0.1:8888")
    os.environ["ADJ_INSECURE"] = "1"
    auid, tok, net = device_state()
    farm = json.load(open(os.path.join(HERE, "farm_win_result.json")))
    last = farm["runs"][-1]
    gps = last["gaid"]
    print("device AdjustAttribution: token=%s network=%s" % (tok, net))
    print("farm last run: %s gaid=%s marker=%s joined=%s"
          % (last["label"], gps, last["creative"],
             last["non_organic_marker_joined"]))
    print("device auid: %s" % auid)
    if not (auid and gps):
        print("missing auid/gps"); return

    url, g = latest_capture(auid)
    runs = []
    if url and g and len(g) == 192:
        print("captured genuine blob: %d B hdr=%s" % (len(g), g[:16].hex()))
        print("captured url: %s" % url[:120])
        flip = bytearray(g); flip[16] ^= 0x01
        for label, blob in (("P1 verbatim genuine (booked?)", g),
                            ("P3 verbatim + body[0] bitflip", bytes(flip))):
            s, b = sp.send_raw(url, blob)
            v = sp.verdict(s, b)
            print("%-32s -> %s %s" % (label, s, v), flush=True)
            runs.append({"label": label, "http": s, "verdict": v})
            time.sleep(2)
    else:
        print("no fresh genuine capture for this auid; running crafted only")

    now = int(time.time())
    st, n, crafted = fc.make_signature(
        now, fc.fmt(now, 322), gps, auid, fc.fmt(now - 30, 431))
    print("maker: status=%s steps=%s blob=%d B hdr=%s"
          % (st, n, len(crafted), crafted[:16].hex()))
    s, b = fc.api_attribution(gps, auid, "")   # maker's proven crafted-poll path
    v = sp.verdict(s, b)
    print("%-32s -> %s %s" % ("P2 crafted poll (maker)", s, v), flush=True)
    runs.append({"label": "P2 crafted poll (maker)", "http": s, "verdict": v})

    json.dump({"gps": gps, "auid": auid, "device_token": tok,
               "device_network": net, "runs": runs},
              open(OUT, "w"), indent=1)
    print("saved", OUT)


if __name__ == "__main__":
    main()
