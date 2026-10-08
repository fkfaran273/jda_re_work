"""diff_funnel_vs_capture.py -- for each signed POST/GET in the golden
capture, diff the genuine field set vs what run_fix1 currently builds."""
import json, sys

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun")
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap")
import importlib.util
spec = importlib.util.spec_from_file_location(
    "run_fix1", r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun\run_fix1.py")
R = importlib.util.module_from_spec(spec)
sys.argv = ["run_fix1.py"]
spec.loader.exec_module(R)

D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))

SIDs = {"session": "42", "click": "43", "attribution": "44"}
GAID = "ca1c27a6-c8f0-40e0-859c-1dd83bc1efbc"
UUID = "00000000-0000-4000-8000-000000000000"

for name, sid in SIDs.items():
    e = next(x for x in D if str(x["sid"]) == sid)
    if e["method"] == "GET":
        import urllib.parse
        real = dict(urllib.parse.parse_qsl(e["url"].split("?", 1)[1], keep_blank_values=True))
    else:
        real = e["body"] if isinstance(e["body"], dict) else json.loads(e["body"])

    if name == "session":
        ours = R.build_session_request(GAID, UUID, 1791282820, click_sec=1791282737)
    elif name == "click":
        ours = R.build_click_request(GAID, UUID, 1791282821,
                                     "adjust_reftag=X&utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_",
                                     click_sec=1791282737)
    else:
        ours = R.build_attribution_request(GAID, UUID, 1791282824)

    rk, ok = set(real.keys()), set(ours.keys())
    print("=== ", name)
    print("  missing in ours (genuine-only):", sorted(rk - ok))
    print("  extra in ours   (wrong for this capture):", sorted(ok - rk))
