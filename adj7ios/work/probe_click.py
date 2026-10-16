import os, sys, time, uuid, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
import run_install_ios as R

idfa = R.new_idfa()
ip = os.environ.get("FUNNEL_IP", "103.25.128." + str(int(time.time()) % 254 + 1))
url = R._subst(R.LINK, idfa, ip)
print("IDFA:", idfa)
print("URL :", url)
reftag, click_sec = R.open_click_link(idfa)
print("reftag:", reftag, "| click_server_sec:", click_sec)
