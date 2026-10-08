import re
import sys
import urllib.parse
from datetime import datetime, timezone, timedelta

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun")
import adj7_pure as sg

txt = open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payruki_again\raw\41_c.txt",
           encoding="utf-8").read()
body = txt.split("Content-Length: 1124", 1)[1]
f = dict(urllib.parse.parse_qsl(body.strip(), keep_blank_values=True))
pat = re.compile(r'signature="([0-9A-Fa-f]+)"')
blob = bytes.fromhex(pat.search(txt).group(1))


def sec(s):
    u = s.replace("Z+0530", "")
    dt = datetime.strptime(u.split(".")[0], "%Y-%m-%dT%H:%M:%S")
    return int((dt - timedelta(hours=5, minutes=30)).replace(
        tzinfo=timezone.utc).timestamp())


cs, ss = sec(f["created_at"]), sec(f["sent_at"])
print("created:", f["created_at"], cs)
print("sent   :", f["sent_at"], ss)
print("header==make_header(created):", sg.make_header(cs) == blob[:16])
print("header==make_header(sent)   :", sg.make_header(ss) == blob[:16])
print("tag_ok:", sg.verify_tag(blob))
