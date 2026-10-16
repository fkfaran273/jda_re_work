import os, sys, time, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
import run_install_ios as R

idfa = R.new_idfa()
ip = "103.25.128.86"
url = R._subst(R.LINK, idfa, ip)
print("URL:", url, flush=True)
st, hd, tx = R._get(url)
print("status:", st, flush=True)
print("date:", hd.get("date"), flush=True)
loc = hd.get("location") or hd.get("Location")
print("location:", (loc or "")[:400], flush=True)
print("set-cookie:", (hd.get("set-cookie") or hd.get("Set-Cookie") or "")[:200], flush=True)
print("body head:", tx[:200].replace("\n", " "), flush=True)
