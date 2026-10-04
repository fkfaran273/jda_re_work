import sys, time, json, base64
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev")
from transport_test import send_httpclient, summarize
# wait until 13:41:00 UTC (window opened 13:40:08; add margin)
target = time.mktime(time.strptime("2026-09-27T13:41:00", "%Y-%m-%dT%H:%M:%S")) - time.timezone
now = time.time()
print("waiting %ds for window..." % max(0, target - now))
time.sleep(max(0, target - now))
cap = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\transport\capture_parsed.json"))
body = open(r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\transport\session_body.txt").read()
flip = bytearray(base64.b64decode(cap["session_blob_b64"])); flip[0] ^= 1
st, txt, el = send_httpclient(base64.b64encode(bytes(flip)).decode(), body)
r = summarize("FLIP-window", st, txt, el)
json.dump([r], open(r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\transport\flip_window_result.json", "w"), indent=1)
