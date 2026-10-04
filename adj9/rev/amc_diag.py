# amc_diag.py - after a failed identity gate: what does the device hold NOW?
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import farm_win as fw
gaid = fw.get_gaid()
print("GMS adid now : ", gaid)
state = fw.su_file(fw.STATE)
print("ActivityState len:", len(state))
import re
uuids = re.findall(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", state)
print("uuids in state:", [u.decode() for u in uuids][:6])
attr = fw.su_file(fw.ATTR)
print("attribution:", attr[:300])
pid = fw.sh("pidof com.penti.app").strip()
print("app pid:", pid)
