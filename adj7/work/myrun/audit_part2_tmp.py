"""audit_part2_tmp.py -- timeline, click-join, transport (offline)."""
import re, os, sys, json, urllib.parse
from datetime import datetime, timezone
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_fiddler as R

def ts(s):
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z([+-]\d\d)(\d\d)", s)
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    off = int(m.group(3))*3600 + int(m.group(4))*60
    ms = int((m.group(2) or "0").ljust(3,"0")[:3])
    return base.replace(tzinfo=timezone.utc).timestamp() - off + ms/1000.0

def load_body(raw, idx):
    t = open(os.path.join(raw, "%02d_c.txt"%idx), encoding="utf-8", errors="replace", newline="").read()
    return urllib.parse.parse_qsl(t.partition("\r\n\r\n")[2].strip(), keep_blank_values=True)
def load_query(raw, idx):
    t = open(os.path.join(raw, "%02d_c.txt"%idx), encoding="utf-8", errors="replace", newline="").read()
    tgt = t.split("\r\n",1)[0].split(" ")[1]
    return urllib.parse.parse_qsl(urllib.parse.urlsplit(tgt).query, keep_blank_values=True)

NEW = os.path.join(HERE,"saz_new","raw")
S=dict(load_body(NEW,65)); C=dict(load_body(NEW,66)); A1=dict(load_query(NEW,67)); A2=dict(load_query(NEW,68)); E=dict(load_body(NEW,69))
click=ts(C["click_time"])
print("== GENUINE offsets from click_time ==")
for k,v in [("click_time_server",C["click_time_server"]),("install_begin",C["install_begin_time"]),
            ("begin_server",C["install_begin_time_server"]),("installed",C["installed_at"]),
            ("sess_created",S["created_at"]),("sess_sent",S["sent_at"]),
            ("click_created",C["created_at"]),("click_sent",C["sent_at"]),
            ("attr1_created",A1["created_at"]),("attr1_sent",A1["sent_at"]),
            ("attr2_created",A2["created_at"]),("attr2_sent",A2["sent_at"]),
            ("event_created",E["created_at"]),("event_sent",E["sent_at"])]:
    print(f"  {k:16s} {ts(v)-click:+8.3f}  {v}")
print("  sdk_click created - session sent = %.3f" % (ts(C["created_at"])-ts(S["sent_at"])))
print("  attr1 - session sent = %.3f | attr2-attr1 = %.3f | event-attr2 = %.3f" % (
    ts(A1["created_at"])-ts(S["sent_at"]), ts(A2["created_at"])-ts(A1["created_at"]), ts(E["created_at"])-ts(A2["created_at"])))
print()
print("== RUN_FIDDLER constants ==")
print("  INSTALL_AFTER=%s SESSION_AT=%s POLL_DELAYS=%s MINT_SKEW=%s" % (R.INSTALL_AFTER,R.SESSION_AT,R.POLL_DELAYS,R.MINT_SKEW))
print("  MS=",R.MS)
print("  sdk_click sleep=0.35s (genuine 0.287) ; attr poll1 delay 2.6s (genuine sess_sent->attr1 = %.3f)" % (ts(A1["created_at"])-ts(S["sent_at"])))
print("  click_second=int(now)-1 AFTER click chain; T0=click_second; session target=T0+33; installed=T0+8.574")
print("  story order ok: installed(T0+8) < session(T0+33) < click_sent(+33.8) < attr(+36.4). NO inversion.")
print("  header==created==sent second by construction (same sec, ms differ) -- matches genuine rows 65-69 (same-second).")
print("  Row-41 straddle (created 32.979/sent 33.355, header==sent) can never be EMITTED by builder (single sec) -- but signing law (header==sent sec, sign-at-send) is what matters, and runner obeys it.")
print()
print("== CLICK JOIN: reftag freshness scan ==")
import glob
vals={}
for p in glob.glob(os.path.join(HERE,"*.json")):
    try: txt=open(p,encoding="utf-8",errors="replace").read()
    except Exception as e: continue
    for m in re.finditer(r"adjust_reftag=([A-Za-z0-9_-]+)",txt):
        vals.setdefault(m.group(1),[]).append(os.path.basename(p))
    for m in re.finditer(r'"reftag":\s*"([^"]+)"',txt):
        vals.setdefault(m.group(1)[:40],[]).append(os.path.basename(p)+":reftag-field")
for k,v in vals.items(): print(f"  {k}  <- {v}")
print("  duplicates:", {k:v for k,v in vals.items() if len(v)>1} or "NONE -- every live run used a fresh reftag")
print()
print("== CLICK JOIN: adjust-hop fidelity ==")
print("  LINK template:", R.LINK)
print("  _subst: {gaid}->gaid, {sub2}->zt1 (NO {sub2} IN LINK => zt1 never fires), {click_id} unused by template")
print("  open_click_link: _fill_device_id(_subst) then append &gps_adid= if missing => click URL always carries gaid as sub3=+gps_adid")
print("  _fill_device_id fills adj_gps_adid=/gps_adid= empty-or-{macro} in every redirect Location")
print("  strips &ip_address={loop_id} (raw+encoded) before it poisons adjust click")
print("  last_run reftag content: utm_source=VL-Alliance utm_campaign=HM2 utm_content=HM2_1722_ (NO zt1 suffix -- matches genuine HM2_1722_)")
print("  genuine verdict adgroup=HM2_1722_; ours never got past Organic so no adgroup observed")
print()
print("== CLICK JOIN: fingerprint (THE SMOKING GUN CANDIDATE) ==")
import inspect
src=inspect.getsource(R._get)
print(src)
print("  BROWSER_UA defined (line ~110) but _get sends APP_UA (Dalvik)+Client-SDK. BROWSER_HEADERS dict is DEAD CODE (never referenced in _get/open_click_link).")
print("  Affiliate click with Dalvik app-UA + Client-SDK header = bot-like; mobpine still issued reftag, but click may be disqualified server-side.")
print()
print("== CLICK JOIN: early-return (CLICK NEVER FIRED CANDIDATE) ==")
print(inspect.getsource(R.open_click_link))
print("  NOTE: on ANY Location containing referrer=, returns WITHOUT firing that URL.")
print("  If that Location IS the app.adjust.com tracking hop (or its pre-hop), Adjust never logs the click => join impossible => Organic+0001+no ask_in.")
print("  Genuine browser follows the FULL chain to Play (firing adjust hop). Runner short-circuits on first referrer sighting.")
print()
print("== TRANSPORT: _connect ==")
print(inspect.getsource(R._connect))
print(inspect.getsource(R.call))
print("  https: TCP->proxy, CONNECT host:port, 200 check, TLS wrap server_hostname=host (SNI=app.adjust.com). Host single (skip_host=1+explicit). No Proxy-Connection. gzip accept+decompress. Header order verified identical to 65_c/67_c in part-1 audit.")
print("  request-target: POST target=path origin-form over tunneled TLS (correct; Fiddler absolute-form display is artifact). HTTP click hops use absolute-URI (correct for forward proxy).")
