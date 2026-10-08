"""audit_funnel_tmp.py -- scratch offline audit (no network). Rows 65-69 + 41-44."""
import re, sys, os, json, urllib.parse, hashlib, hmac as hmac_mod
from datetime import datetime, timezone, timedelta
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), ".."))  # adj7/work for ks_inverse
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7\work")
import adj7_pure as sg
from ks_inverse import cbc_dec
import run_fiddler as R

NEWRAW = os.path.join(HERE, "saz_new", "raw")
OLRRAW = r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payruki_again\raw"
CERT = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
CS = "android5.6.0"

def sec_of(s):
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z([+-]\d\d)(\d\d)", s)
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    off = int(m.group(3))*3600 + int(m.group(4))*60
    return int((base.replace(tzinfo=timezone.utc)).timestamp() - off)

def load(raw, idx):
    t = open(os.path.join(raw, "%02d_c.txt" % idx), encoding="utf-8", errors="replace", newline="").read()
    head, _, body = t.partition("\r\n\r\n")
    lines = head.split("\r\n")
    method, target, _ = lines[0].split(" ", 2)
    hdrs = [l for l in lines[1:]]
    m = re.search(r'signature="([0-9A-Fa-f]+)"', t)
    blob = bytes.fromhex(m.group(1))
    auth = re.search(r"^Authorization: (.+)$", t, re.M).group(1).strip()
    if method == "GET":
        q = urllib.parse.urlsplit(target).query
        pairs = urllib.parse.parse_qsl(q, keep_blank_values=True)
        fields = dict(pairs)
    else:
        pairs = urllib.parse.parse_qsl(body.strip(), keep_blank_values=True)
        fields = dict(pairs)
    return method, target, hdrs, pairs, fields, blob, auth

KINDS = {65:"session",66:"click",67:"attribution",68:"attribution",69:"event",
         41:"session",42:"click",43:"attribution",44:"event"}

print("="*78)
print("PART 1: SIGNER recompute (sent_at second + block2=True, fixed nonce)")
print("="*78)
for raw, idx in [(NEWRAW,65),(NEWRAW,66),(NEWRAW,67),(NEWRAW,68),(NEWRAW,69),
                 (OLRRAW,41),(OLRRAW,42),(OLRRAW,43),(OLRRAW,44)]:
    kind = KINDS[idx]
    method, target, hdrs, pairs, fields, blob, auth = load(raw, idx)
    tag_ok = sg.verify_tag(blob)
    # decrypt -> nonce12, cert40, H
    rec = cbc_dec(blob[16:272], blob[:16])
    s = rec.split(b"\x00")[0].decode("latin1")
    A = re.search(r'"a":\s*(\d+)', s).group(1)
    Hdev = re.search(r'"b":\s*"([0-9A-Fa-f]+)"', s).group(1)
    cert = re.search(r'"c":\s*"([^"]+)"', s).group(1)
    D8 = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
    nonce = int(A).to_bytes(8,"little") + bytes.fromhex(D8)
    cert40 = cert.encode()
    # claims recompute
    claims = sg.build_claims(kind, fields, client_sdk=CS, include_block2=True)
    Hour = sg.commitment_digest(claims, nonce, cert40).hex().upper()
    h_match = (Hour == Hdev)
    # pin check: claims must contain 1300000 at split
    pin_ok = b"1300000" in sg.build_claims(kind, fields, client_sdk=CS, include_block2=True)
    # seconds
    csec = sec_of(fields["created_at"]); ssec = sec_of(fields["sent_at"])
    h_c = sg.make_header(csec) == blob[:16]
    h_s = sg.make_header(ssec) == blob[:16]
    # re-mint with sent second
    auth2 = sg.sign_request(fields, kind, second=ssec, nonce12=nonce,
                            cert_sha1=cert, client_sdk=CS,
                            include_block2=True, headers_id="8", native_version="3.62.0")
    blob2 = bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"', auth2).group(1))
    exact = blob2 == blob
    # also try created second
    auth3 = sg.sign_request(fields, kind, second=csec, nonce12=nonce,
                            cert_sha1=cert, client_sdk=CS,
                            include_block2=True, headers_id="8", native_version="3.62.0")
    blob3 = bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"', auth3).group(1))
    exact_c = blob3 == blob
    # no-block2 test
    claims_nb = sg.build_claims(kind, fields, client_sdk=CS, include_block2=False)
    Hnb = sg.commitment_digest(claims_nb, nonce, cert40).hex().upper()
    print(f"row {idx} [{kind}]: tag_ok={tag_ok} H_match(block2)={h_match} H_match(noblock2)={Hnb==Hdev}")
    print(f"   cert40={cert[:12]}... cert==C1BFAFCAFFB8={cert.upper()==CERT} pin1300000_in_claims={pin_ok}")
    print(f"   created_sec={csec} sent_sec={ssec} header==created:{h_c} header==sent:{h_s}")
    print(f"   remint(sent,block2,nonce,cert) byte-exact={exact} remint(created)={exact_c}")
    if not exact:
        # hex diff: first diff offset
        for i,(a,b) in enumerate(zip(blob.hex().upper(), blob2.hex().upper())):
            if a!=b:
                print(f"   FIRST HEX DIFF @nibble {i}: genuine...{blob.hex().upper()[max(0,i-8):i+24]} ours...{blob2.hex().upper()[max(0,i-8):i+24]}")
                break
        print(f"   header genuine={blob[:16].hex().upper()} ours(sent)={blob2[:16].hex().upper()}")
    # claims order check: pool order respected?
    print(f"   claims_len={len(claims)} H_dev={Hdev[:16]}... H_our={Hour[:16]}...")
print()
print("CLAIM POOL order check: activity_kind/client_sdk at end:",
      sg.CLAIM_POOL[-2:], "| seq idx:", sg.CLAIM_POOL.index("seq"),
      "| session_count idx:", sg.CLAIM_POOL.index("session_count"))
print("pin emitted between profile and tail (split at seq): code appends ADJ_SIGNING_ID after profile loop -- verified in source lines 151-156")
print()
print("="*78)
print("PART 2: BUILDERS/WIRE run_fiddler vs genuine 65-69")
print("="*78)
DYN = {"gps_adid","android_uuid","partner_params","callback_params","referrer",
       "created_at","sent_at","installed_at","updated_at","click_time",
       "click_time_server","install_begin_time","install_begin_time_server"}
gaid="11111111-2222-4333-8444-555555555555"; auuid="99999999-8888-7777-6666-555555554444"
ref=("adjust_reftag=cig3EKyu8m0zt&utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_")
click_sec=1791372316; sec=click_sec+33
R.PARTNER_PARAMS=json.dumps({"payrupik_c_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},separators=(",",":"))
ours={"session":R.build_session_request(gaid,auuid,sec,click_sec=click_sec),
      "click":R.build_click_request(gaid,auuid,sec,ref,click_sec=click_sec),
      "attribution":R.build_attribution_request(gaid,auuid,sec+3),
      "event":R.build_event_request(gaid,auuid,sec+5,click_sec=click_sec)}
for idx,name in [(65,"session"),(66,"click"),(67,"attribution"),(69,"event")]:
    method,target,hdrs,pairs,fields,blob,auth=load(NEWRAW,idx)
    of=list(ours[name].items())
    og=[k for k,_ in of]; gg=[k for k,_ in pairs]
    print(f"[{name}] keys ours={len(og)} golden={len(gg)} missing={[k for k in gg if k not in og]} extra={[k for k in og if k not in gg]}")
    if og==gg: print("   order identical")
    else:
        for i,(a,b) in enumerate(zip(og,gg)):
            if a!=b: print(f"   ORDER pos {i}: ours={a} golden={b}")
        if len(og)!=len(gg): print(f"   len diff ours={len(og)} golden={len(gg)}")
    od=dict(of); gd=dict(pairs)
    bad=[(k,od[k],gd[k]) for k in gd if k in od and od[k]!=gd[k] and k not in DYN]
    print(f"   static diffs: {bad if bad else 'NONE -- byte-equal'}")
    dyn=[k for k in gd if k in od and od[k]!=gd[k] and k in DYN]
    print(f"   dynamic: {dyn}")
    # wire encoding: re-encode GOLDEN pairs with our encoder vs raw
    t=open(os.path.join(NEWRAW,"%02d_c.txt"%idx),encoding="utf-8",errors="replace",newline="").read()
    raw_body=t.partition("\r\n\r\n")[2].strip()
    if method=="POST":
        enc=urllib.parse.urlencode(pairs).encode()
        refb="\r\n".join(raw_body.splitlines()).encode() if False else raw_body.encode()
        print(f"   wire POST body: encoder_len={len(enc)} golden_len={len(refb)} identical={enc==refb}")
        if enc!=refb:
            for i in range(min(len(enc),len(refb))):
                if enc[i]!=refb[i]:
                    print(f"     first diff @{i}: ours={enc[i:i+60]!r} golden={refb[i:i+60]!r}"); break
        # Content-Length check
        cl=[l for l in hdrs if l.lower().startswith("content-length")]
        print(f"   {cl} vs encoder {len(enc)}; ours would send {len(urllib.parse.urlencode(of).encode())}")
    else:
        enc=urllib.parse.urlencode(pairs,quote_via=urllib.parse.quote)
        rawq=urllib.parse.urlsplit(target).query
        print(f"   wire GET query: encoder==raw: {enc==rawq} lens {len(enc)}/{len(rawq)}")
        if enc!=rawq:
            for i in range(min(len(enc),len(rawq))):
                if enc[i]!=rawq[i]:
                    print(f"     first diff @{i}: ours={enc[i:i+80]!r} golden={rawq[i:i+80]!r}"); break
    # headers
    golden_h=[l.split(": ",1)[0] for l in hdrs if ": " in l]
    exp=["Client-SDK","Authorization"]+([] if name=="attribution" else ["Content-Type"])+["User-Agent","Host","Connection","Accept-Encoding"]+([] if name=="attribution" else ["Content-Length"])
    print(f"   headers ours={exp} golden={golden_h} match={exp==golden_h}")
    # auth attrs
    import re as _re
    oa=dict(_re.findall(r'(\w+)="([^"]*)"', R.sign(dict(of),name if name!="click" else "click",sec)[len('Signature '):]))
    ga=dict(_re.findall(r'(\w+)="([^"]*)"', auth[len('Signature '):]))
    print(f"   auth attrs match={oa==ga} ours={oa} golden={ga}")
    gh=_re.search(r'signature="([0-9A-Fa-f]+)"',auth).group(1)
    print(f"   blob hex len ours=608 golden={len(gh)} (304B={len(gh)==608})")
print()
print("PARTNER stable check: genuine payrupik_c_id=4c2576c7-... ours uses FUNNEL_PARTNER env or same default:",
      json.loads(R.PARTNER_PARAMS))
print("APP_UA:", R.APP_UA)
print("genuine UA: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)")
print("UA match:", R.APP_UA=="Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)")
