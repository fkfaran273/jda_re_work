"""_redrive2.py — the user's test, with a CORRECT signature.

Replay the genuine non-organic /session + /sdk_click (GAID d016e7e4, tracker
24pxw9rl) re-signed with OUR signer using the DEVICE-VERIFIED head
(0x2b, 0x48), and poll /attribution.

Arms:
  SAME  - on the original GAID (attribution there is already stored/immutable)
  FRESH - identical click/timings on a brand-new GAID (the real test)
"""
import base64, gzip, http.client, json, os, struct, sys, time, urllib.parse, uuid
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod
import nonorg_redrive as R

UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"

def mint(params, kind, sec):
    claims = dict(params)
    for k, v in (("adj_verification", R.ADJ_V), ("adj_signing_id","1500000"),
                 ("headers_id","10"), ("native_version","5.0.0"),
                 ("activity_kind",kind), ("client_sdk","android5.7.0")):
        claims.setdefault(k, v)
    padded, unpadded = M.claims_for_law(claims, kind)
    d0w, d2w, d4w = Fmod.region(sec, M.DEFAULT_PID, 0, head=M.DEVICE_SELECTORS)
    by = {0:(36, b''.join(w.to_bytes(4,'big') for w in d0w)),
          9:(5, bytes.fromhex('fad0f10d60f93c17937b2f1eb6c09691ae7d74bd')),
          8:(4, bytes.fromhex('bffffffffffffd1f0007000000000000')),
          4:(8, b''.join(w.to_bytes(4,'big') for w in d4w)),
          2:(1, d2w.to_bytes(4,'big')), 7:(1, struct.pack('>I',unpadded)),
          10:(len(padded)//4, padded), 5:(1,b'\0'*4), 6:(1,b'\0'*4),
          1:(0,b''), 3:(0,b'')}
    blob, info = M.finex_mint([(by[i][0],0,by[i][1]) for i in M.VA_ORDER], sec)
    return blob, info

def run(mode, gps, auid):
    sp = R.rebase(R.load('1_c.txt'), gps, auid, 0)
    cp = R.rebase(R.load('2_c.txt'), gps, auid, 0)
    rec = {"mode": mode, "gps": gps, "skeys": len(sp), "ckeys": len(cp),
           "head": tuple(hex(x) for x in M.DEVICE_SELECTORS)}
    sec = int(time.time())
    bs, isess = mint(sp, 'session', sec)
    rec['session_mint'] = isess.get('status')
    st, bd = R.req("POST", "/session", sp, R.auth_of(bs))
    rec['session'] = [st, bd[:180]]
    bc, ic = mint(cp, 'click', sec)
    rec['click_mint'] = ic.get('status')
    stc, bdc = R.req("POST", "/sdk_click", cp, R.auth_of(bc))
    rec['sdk_click'] = [stc, bdc[:180]]
    for w in (10, 30, 75, 150):
        time.sleep(w)
        ap = {"app_token":"jut9tib0eeps","gps_adid":gps,"android_uuid":auid,
              "initiated_by":"backend","environment":"production",
              "needs_response_details":"1","attribution_deeplink":"1",
              "created_at":sp["created_at"],"app_version":"3.13.9",
              "api_level":"31","os_version":"12","device_name":"moto g42",
              "device_type":"phone","os_name":"android",
              "package_name":"com.penti.app","gps_adid_src":"service",
              "tracking_enabled":"1","foreground":"1","gps_adid_attempt":"1",
              "offline_mode_enabled":"0","ui_mode":"1"}
        ba,_ = mint(ap, 'attribution', int(time.time()))
        sa, bda = R.req("GET", "/attribution", ap, R.auth_of(ba))
        rec['verdict'] = R.score(sa, bda)
        rec['last'] = [sa, bda[:260]]
        print("   %s +%ds: %s" % (mode, w, rec['verdict']), flush=True)
        if 'NON-ORGANIC' in rec['verdict']: break
    return rec

out = []
print("=== SAME GAID %s ===" % R.REAL_GAID, flush=True)
out.append(run('SAME', R.REAL_GAID, R.REAL_AUID))
print("=== FRESH GAID ===", flush=True)
out.append(run('FRESH', str(uuid.uuid4()), str(uuid.uuid4())))
json.dump(out, open('redrive2_result.json','w'), indent=1)
print("\n=== VERDICT (original device record: VKM Digital Yeni / 24pxw9rl) ===")
for r in out:
    print("  %-6s -> %s" % (r['mode'], r['verdict']))
