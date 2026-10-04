"""_iso_ref.py — is the referrer the gate?

The replay WORKED with referrer = 'utm_source=(not set)&utm_medium=(not set)'.
The fresh synthetic FAILED with referrer = 'adjust_reftag=...&utm_source=VKM...'.
Everything else is identical modulo timestamps.  Run 3 arms on fresh GAIDs,
replaying the genuine params and varying ONLY the referrer.
"""
import json, sys, time, uuid
sys.path.insert(0, '.')
import mint_pipeline as M
import nonorg_redrive as R
import click_bind_chain as CBC
import offline_funnel_freshregion as FFN

def run(tag, referrer, do_click):
    gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
    rec = {"tag": tag, "gps": gps, "referrer": referrer[:70], "tracker_click": do_click}
    if do_click:
        code, r, _ = CBC.tracker_click(CBC.expand(FFN.LINK, gps), gps)
        rec['click_http'] = code
        if r: referrer = r
    sp = R.rebase(R.load('1_c.txt'), gps, auid, 0)
    cp = R.rebase(R.load('2_c.txt'), gps, auid, 0)
    cp['referrer'] = referrer
    sec = int(time.time())
    import _redrive2 as RD
    blob_s, _ = RD.mint(sp, 'session', sec)
    st, bd = R.req("POST", "/session", sp, R.auth_of(blob_s))
    rec['session'] = [st, bd[:120]]
    blob_c, _ = RD.mint(cp, 'click', sec)
    stc, bdc = R.req("POST", "/sdk_click", cp, R.auth_of(blob_c))
    rec['sdk_click'] = [stc, bdc[:120]]
    for w in (12, 40):
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
        ba,_ = RD.mint(ap, 'attribution', int(time.time()))
        sa, bda = R.req("GET", "/attribution", ap, R.auth_of(ba))
        rec['verdict'] = R.score(sa, bda)
        print("  %-22s +%ds: %s" % (tag, w, rec['verdict']), flush=True)
        if 'NON-ORGANIC' in rec['verdict']: break
    return rec

out = []
arms = [
  ("R0-placeholder-noclick", "utm_source=(not%20set)&utm_medium=(not%20set)", False),
  ("R1-ourreftag-noclick",   "adjust_reftag=ZZZZZZZZZZZZ&utm_source=VKM+Digital+Yeni&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic", False),
  ("R2-ourclick-ourreftag",  None, True),
]
for tag, ref, dc in arms:
    print("=== %s ===" % tag, flush=True)
    out.append(run(tag, ref, dc))
json.dump(out, open('iso_ref_result.json','w'), indent=1)
print("\n=== SUMMARY ===")
for r in out:
    print("  %-24s -> %s" % (r['tag'], r['verdict']))
