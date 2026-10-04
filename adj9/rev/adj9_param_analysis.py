"""adj9_param_analysis.py — OFFLINE param-level diff: REAL DEVICE SAZ session
vs our Python mint path.  Read-only on existing files; writes only NEW files
beside itself in rev/.

Outputs (all NEW, in rev/):
  saz_params.json   every param of the 3 captured requests
  py_params.json    the same 3 param dicts our Python path builds (no send)
  param_diff.json   device-only / python-only / same-name-different-value
  PARAM_DIFF.md     human-readable diff + claim-length gap analysis
  moto_g42_profile.json  corrected device profile + time shape + CTIT

NO network. NO adb. NO device.  Importing this module only reads JSON.
"""
import datetime
import json
import os
import sys
import urllib.parse
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_full_chain as FC          # S1P/S2P templates, DEV, fmt
import run_funnel as RF               # DEVICE_JSON, dev_from_json, ua_from_json
import mint_pipeline as MP            # claims_from_wire, INTERNAL_CLAIMS
import desc10_law as D                # build_desc10, desc10_keys

SAZ = r"C:\Users\Apps\Downloads\penti_android_test.saz"


# ---------------------------------------------------------------- helpers
def parse_stamp(s):
    """'2026-09-14T17:53:07.753Z+0530' -> epoch seconds (float)."""
    body, off = s.rsplit("Z", 1)
    sgn = 1 if off[0] == "+" else -1
    hh, mm = int(off[1:3]), int(off[3:5])
    dt = datetime.datetime.strptime(body, "%Y-%m-%dT%H:%M:%S.%f")
    dt = dt.replace(tzinfo=datetime.timezone.utc) - \
        datetime.timedelta(minutes=sgn * (hh * 60 + mm))
    return dt.timestamp()


def read_saz_requests():
    """Return {'session': qsl, 'sdk_click': qsl, 'attribution': qsl} of
    (name, value) pairs in wire order, plus headers."""
    z = zipfile.ZipFile(SAZ)
    out = {}
    for sess, name in ((1, "session"), (2, "sdk_click"), (3, "attribution")):
        raw = z.read("raw/%d_c.txt" % sess).decode("utf-8", "replace")
        head, _, body = raw.partition("\r\n\r\n")
        if not body:
            head, _, body = raw.partition("\n\n")
        reqline = head.splitlines()[0]
        if "?" in reqline:
            # GET: request-line = METHOD SP target SP HTTP/x.y; the query is
            # the part after '?' and NEVER contains a raw space (spaces are
            # %20), so token 2 is the exact query without the version suffix.
            qs = reqline.split("?", 1)[1].split(" ", 1)[0]
        else:
            qs = body
        qsl = urllib.parse.parse_qsl(qs, keep_blank_values=True)
        out[name] = qsl
    z.close()
    return out


# ------------------------------------------------- python path (no send)
def set_profile_redmi():
    """Reproduce _funnel_env: DEV/UA from the Redmi/Android-15 DEVICE_JSON."""
    dev = json.loads(RF.DEVICE_JSON)
    FC.DEV, FC.UA = RF.dev_from_json(dev), RF.ua_from_json(dev)
    FC.OFF_MINUTES, FC.OFF_LABEL = 330, "+0530"
    FC.ADD_IDFA = False
    return dev


def py_session_params(sec, gps, auid, ins):
    """Mirror mint_pipeline.api_session_mint param construction exactly."""
    p = dict(FC.S1P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": FC.fmt(sec - 1, 928).decode(),
              "sent_at": FC.fmt(sec - 1, 942).decode(),
              "installed_at": ins, "updated_at": ins})
    p.update(FC.DEV)
    p.pop("no_sim", None)
    if FC.DEV.get("no_sim"):
        p.pop("mcc", None)
        p.pop("mnc", None)
    p.pop("install_version", None)
    return p


def py_click_params(sec, gps, auid, referrer, t_track, tb, ins):
    """Mirror mint_pipeline.api_sdk_click_mint param construction exactly."""
    p = dict(FC.S2P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": FC.fmt(sec - 1, 961).decode(),
              "sent_at": FC.fmt(sec - 1, 970).decode(),
              "installed_at": ins,
              "referrer": referrer, "source": "install_referrer",
              "referrer_api": "google",
              "click_time": FC.fmt(t_track, 0).decode(),
              "click_time_server": FC.fmt(t_track - 2, 0).decode(),
              "install_begin_time": FC.fmt(tb, 0).decode(),
              "install_begin_time_server": FC.fmt(tb - 2, 0).decode()})
    p.update(FC.DEV)
    p.pop("no_sim", None)
    if FC.DEV.get("no_sim"):
        p.pop("mcc", None)
        p.pop("mnc", None)
    if FC.ADD_IDFA:
        p["idfa"] = gps
    return p


def py_attr_params(sec, gps, auid, initiated_by="backend"):
    """Mirror adj9_full_chain.api_attribution param construction exactly."""
    return {
        "initiated_by": initiated_by, "gps_adid_attempt": "1",
        "api_level": FC.DEV["api_level"],
        "app_version": FC.DEV["app_version"], "app_token": FC.APP_TOKEN,
        "os_version": FC.DEV["os_version"],
        "created_at": FC.fmt(sec - 1, 666).decode(), "device_type": "phone",
        "gps_adid": gps, "foreground": "1",
        "android_uuid": auid, "sent_at": FC.fmt(sec - 1, 696).decode(),
        "offline_mode_enabled": "0", "device_name": FC.DEV["device_name"],
        "environment": "production", "needs_response_details": "1",
        "attribution_deeplink": "1", "package_name": "com.penti.app",
        "os_name": "android", "ui_mode": "1", "gps_adid_src": "service",
        "tracking_enabled": "1",
    }


# ---------------------------------------------------------------- diffing
def diff_dict(dev, py):
    dev_keys, py_keys = set(dev), set(py)
    device_only = sorted(dev_keys - py_keys)
    python_only = sorted(py_keys - dev_keys)
    same_diff = sorted(k for k in (dev_keys & py_keys) if dev[k] != py[k])
    return {
        "device_only": {k: dev[k] for k in device_only},
        "python_only": {k: py[k] for k in python_only},
        "same_name_different_value": {
            k: {"device": dev[k], "python": py[k]} for k in same_diff},
        "counts": {"device": len(dev), "python": len(py),
                   "device_only": len(device_only),
                   "python_only": len(python_only),
                   "same_name_different_value": len(same_diff)},
    }


def claim_map_from_params(params, kind):
    """claims_from_wire — requires every law key present in params (or internal)."""
    return MP.claims_from_wire(params, kind)


def claim_len_delta(dev_claims, py_claims, kind):
    keys = D.desc10_keys(kind, dev_claims)
    rows = []
    for k in keys:
        dv = dev_claims.get(k, "")
        pv = py_claims.get(k, "")
        rows.append((k, len(dv), len(pv), len(pv) - len(dv)))
    return rows


# ------------------------------------------------------------------ main
def main():
    saz = read_saz_requests()
    saz_dict = {k: dict(v) for k, v in saz.items()}

    # --- device claim lengths (from the ACTUAL captured params) ---
    # desc10 kind -> saz_dict key
    KIND2SAZ = {"session": "session", "click": "sdk_click",
                "attribution": "attribution"}
    dev_claims = {}
    for kind, skey in KIND2SAZ.items():
        dev_claims[kind] = claim_map_from_params(saz_dict[skey], kind)
    dev_len = {k: len(D.build_desc10(v, k)) for k, v in dev_claims.items()}

    # --- python path: use the DEVICE's own identity + times as inputs so the
    #     diff isolates PROFILE deltas (times are same-length anyway). ---
    set_profile_redmi()
    dev_s = saz_dict["session"]
    gps = dev_s["gps_adid"]
    auid = dev_s["android_uuid"]
    ins = dev_s["installed_at"]                       # installed_at string
    sec = int(parse_stamp(dev_s["created_at"])) + 1   # so created_at ~ device
    c = saz_dict["sdk_click"]
    t_track = int(parse_stamp(c["click_time"]))
    tb = int(parse_stamp(c["install_begin_time"]))
    referrer = c["referrer"]                          # device's referrer
    # fetch params use a later created_at; use its second for attribution
    a = saz_dict["attribution"]
    sec_a = int(parse_stamp(a["created_at"])) + 1

    py = {
        "session": py_session_params(sec, gps, auid, ins),
        "sdk_click": py_click_params(sec, gps, auid, referrer, t_track, tb, ins),
        "attribution": py_attr_params(sec_a, gps, auid, "backend"),
    }
    py_claims = {kind: claim_map_from_params(py[KIND2SAZ[kind]], kind)
                 for kind in ("session", "click", "attribution")}
    py_len = {k: len(D.build_desc10(v, k)) for k, v in py_claims.items()}

    # --- write the two param dumps ---
    with open(os.path.join(HERE, "saz_params.json"), "w", encoding="utf-8") as f:
        json.dump({k: dict(v) for k, v in saz.items()}, f, indent=1,
                  ensure_ascii=False, sort_keys=True)
    with open(os.path.join(HERE, "py_params.json"), "w", encoding="utf-8") as f:
        json.dump(py, f, indent=1, ensure_ascii=False, sort_keys=True)

    # --- three-way param diff ---
    diffs = {kind: diff_dict(saz_dict[kind], py[kind])
             for kind in ("session", "sdk_click", "attribution")}

    # --- corrected claim set: the DEVICE's own params (moto g42 profile) ---
    corr_claims = {kind: claim_map_from_params(saz_dict[KIND2SAZ[kind]], kind)
                   for kind in ("session", "click", "attribution")}
    corr_len = {k: len(D.build_desc10(v, k)) for k, v in corr_claims.items()}

    # --- claim-length per-key delta (device vs python-redmi), session ---
    sd_rows = claim_len_delta(dev_claims["session"], py_claims["session"],
                              "session")

    # --- CTIT from the device's time shape ---
    click_epoch = parse_stamp(c["click_time"])
    ib_epoch = parse_stamp(c["install_begin_time"])
    ins_epoch = parse_stamp(dev_s["installed_at"])
    crt_epoch = parse_stamp(dev_s["created_at"])
    ctit = ins_epoch - click_epoch
    ctit_ib = ib_epoch - click_epoch

    # --- corrected device profile (the DEV dict + UA + time shape) ---
    profile = {
        "_comment": "Corrected moto g42 device profile. Use as FC.DEV (the "
                    "adj9_full_chain DEV dict) and FC.UA. No mcc/mnc. This is "
                    "the same shape the winning device sent; it reproduces the "
                    "device's exact param set via dev_from_json-equivalent "
                    "fields (see PARAM_DIFF.md for wiring).",
        "DEV": {
            "api_level": "31", "os_version": "12", "device_name": "moto g42",
            "device_manufacturer": "motorola",
            "hardware_name": "S2SE32.28-28-4",
            "os_build": "S2SE32.28-28-4", "app_version": "3.13.9",
            "install_version": "3.13.9", "language": "tr",
            "display_width": "1080", "display_height": "2237",
            "screen_density": "high", "no_sim": True,
        },
        "UA": "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 "
              "Build/S2SE32.28-28-4)",
        "OFF_MINUTES": 330, "OFF_LABEL": "+0530", "ADD_IDFA": False,
        "device_json_fields": {
            "sdk": "31", "os_version": "12", "model": "moto g42",
            "brand": "motorola", "mainboard": "S2SE32.28-28-4",
            "build": "S2SE32.28-28-4", "locale.language": "tr",
            "display_metrics.xpx": "1080", "display_metrics.ypx": "2237",
            "display_metrics.density_dpi": "hdpi",
        },
        "time_shape": {
            "click_time": c["click_time"],
            "install_begin_time": c["install_begin_time"],
            "installed_at": dev_s["installed_at"],
            "created_at": dev_s["created_at"],
        },
        "ctit": {
            "click_to_install_seconds": round(ctit, 3),
            "click_to_install_begin_seconds": round(ctit_ib, 3),
            "note": "CTIT = installed_at - click_time = %.3f s (%.2f min)" % (
                ctit, ctit / 60.0),
        },
    }
    with open(os.path.join(HERE, "moto_g42_profile.json"), "w",
              encoding="utf-8") as f:
        json.dump(profile, f, indent=1, ensure_ascii=False)

    # --- the corrected CLAIM SET (the exact key->value maps that reproduce
    #     the device's #10 claim-string length for all three kinds) ---
    corrected_claims_doc = {
        "session": {"claims": corr_claims["session"],
                    "unpadded_len": corr_len["session"],
                    "padded_len": corr_len["session"]
                                  + (-corr_len["session"] % 4)},
        "click": {"claims": corr_claims["click"],
                  "unpadded_len": corr_len["click"],
                  "padded_len": corr_len["click"] + (-corr_len["click"] % 4)},
        "attribution": {"claims": corr_claims["attribution"],
                        "unpadded_len": corr_len["attribution"],
                        "padded_len": corr_len["attribution"]
                                      + (-corr_len["attribution"] % 4)},
    }
    with open(os.path.join(HERE, "corrected_claims.json"), "w",
              encoding="utf-8") as f:
        json.dump(corrected_claims_doc, f, indent=1, ensure_ascii=False)

    # --- the full diff artifact ---
    diff_doc = {
        "param_counts": {
            "device": {k: len(saz_dict[k]) for k in saz_dict},
            "python": {k: len(py[k]) for k in py},
        },
        "claim_lengths": {
            "device_from_saz": dev_len,
            "python_redmi": py_len,
            "corrected_device": corr_len,
        },
        "diffs": diffs,
        "session_claim_key_length_delta": [
            {"key": k, "device_len": dl, "python_len": pl, "delta": d}
            for (k, dl, pl, d) in sd_rows if d != 0 or k in (
                "device_name", "hardware_name", "os_build")
        ],
        "session_claim_total": {
            "device_unpadded": dev_len["session"],
            "python_unpadded": py_len["session"],
            "gap": py_len["session"] - dev_len["session"],
        },
    }

    # --- VERIFY: the CORRECTED PROFILE (moto_g42_profile.json), fed through
    #     the REAL Python builders, reproduces the device's claim lengths and
    #     the device's exact session param set (43 keys, no mcc/mnc).
    prof = profile
    FC.DEV, FC.UA = dict(prof["DEV"]), prof["UA"]
    FC.OFF_MINUTES, FC.OFF_LABEL = prof["OFF_MINUTES"], prof["OFF_LABEL"]
    FC.ADD_IDFA = prof["ADD_IDFA"]
    verify = {}
    v_ses = py_session_params(sec, gps, auid, ins)
    v_clk = py_click_params(sec, gps, auid, referrer, t_track, tb, ins)
    v_att = py_attr_params(sec_a, gps, auid, "backend")
    for kind, params in (("session", v_ses), ("click", v_clk),
                         ("attribution", v_att)):
        cm = claim_map_from_params(params, kind)
        raw = len(D.build_desc10(cm, kind))
        verify[kind] = {"claim_unpadded": raw,
                        "claim_padded": raw + (-raw % 4),
                        "n_params": len(params)}
    verify["session_keys_match_device"] = (
        sorted(v_ses.keys()) == sorted(saz_dict["session"].keys()))
    verify["session_mcc_mnc_present"] = [("mcc" in v_ses), ("mnc" in v_ses)]
    # claim-relevant session field values must equal the device's
    for k in ("device_name", "hardware_name", "os_build", "api_level",
              "os_version"):
        verify.setdefault("session_claim_values", {})[k] = {
            "device": dev_claims["session"][k],
            "corrected": claim_map_from_params(v_ses, "session")[k],
        }
    diff_doc["corrected_profile_verification"] = verify
    set_profile_redmi()  # restore module state
    with open(os.path.join(HERE, "param_diff.json"), "w", encoding="utf-8") as f:
        json.dump(diff_doc, f, indent=1, ensure_ascii=False)

    # ------------------------------------------------------------ report
    print("=" * 72)
    print("PARAM COUNTS  (device / python)")
    for k in ("session", "sdk_click", "attribution"):
        print("  %-12s device=%2d  python=%2d" % (
            k, len(saz_dict[k]), len(py[k])))
    print("CLAIM LENGTHS (#10, unpadded)")
    print("  device-from-SAZ   session=%d  click=%d  attribution=%d" % (
        dev_len["session"], dev_len["click"], dev_len["attribution"]))
    print("  python (Redmi)    session=%d  click=%d  attribution=%d" % (
        py_len["session"], py_len["click"], py_len["attribution"]))
    print("  corrected (moto)  session=%d  click=%d  attribution=%d" % (
        corr_len["session"], corr_len["click"], corr_len["attribution"]))
    print("SESSION GAP: python %d vs device %d = %d" % (
        py_len["session"], dev_len["session"],
        py_len["session"] - dev_len["session"]))
    print("  per-key nonzero length deltas (python - device):")
    for (k, dl, pl, d) in sd_rows:
        if d:
            print("    %-28s dev=%2d py=%2d  %+d" % (k, dl, pl, d))
    print("CTIT installed_at-click_time = %.3f s" % ctit)
    print("=" * 72)

    # write PARAM_DIFF.md
    write_md(saz_dict, py, diffs, dev_len, py_len, corr_len, sd_rows,
             ctit, ctit_ib)
    print("wrote saz_params.json, py_params.json, param_diff.json, "
          "PARAM_DIFF.md, moto_g42_profile.json in", HERE)
    return 0


def write_md(saz, py, diffs, dev_len, py_len, corr_len, sd_rows, ctit, ctit_ib):
    L = []
    A = L.append
    A("# Param-level diff — REAL DEVICE (SAZ) vs Python mint path\n")
    A("Ground truth: `penti_android_test.saz` sessions 1/2/3 "
      "(POST /session, POST /sdk_click, GET /attribution). "
      "Device: moto g42, Android 12, api 31, motorola, tr, "
      "S2SE32.28-28-4, high, 1080x2237, no mcc/mnc.\n")
    A("Python path: `mint_pipeline` builders over the Redmi/Android-15 "
      "`run_funnel.DEVICE_JSON` profile. Built offline, no send.\n")
    A("## 1. Param counts\n")
    A("| kind | device | python |")
    A("|---|---:|---:|")
    for k in ("session", "sdk_click", "attribution"):
        A("| %s | %d | %d |" % (k, len(saz[k]), len(py[k])))
    A("")
    A("## 2. Claim-string (#10) lengths\n")
    A("| kind | device (SAZ) | python (Redmi) | corrected (moto g42) |")
    A("|---|---:|---:|---:|")
    for k, dk in (("session", "session"), ("click", "sdk_click"),
                  ("attribution", "attribution")):
        A("| %s | %d | %d | %d |" % (dk, dev_len[k], py_len[k], corr_len[k]))
    A("")
    A("## 3. Three-way param diff (per kind)\n")
    for kind in ("session", "sdk_click", "attribution"):
        d = diffs[kind]
        A("### %s\n" % kind)
        A("- device-only params: %d" % len(d["device_only"]))
        for k, v in d["device_only"].items():
            A("  - `%s` = `%s`" % (k, v))
        A("- python-only params: %d" % len(d["python_only"]))
        for k, v in d["python_only"].items():
            A("  - `%s` = `%s`" % (k, v))
        A("- same-name-different-value: %d" %
          len(d["same_name_different_value"]))
        for k, v in d["same_name_different_value"].items():
            A("  - `%s`: device=`%s` python=`%s`" % (k, v["device"], v["python"]))
        A("")
    A("## 4. Cause of the session claim-length gap\n")
    A("The desc10 law signs only the law keys; profile fields that ARE law "
      "keys (device_name, hardware_name, os_build, api_level, os_version) "
      "change the concatenated claim length directly.\n")
    A("Per-key session claim value lengths (python_redmi - device):\n")
    A("| key | device | python | delta |")
    A("|---|---:|---:|---:|")
    for (k, dl, pl, d) in sd_rows:
        if d != 0:
            A("| `%s` | %d | %d | %+d |" % (k, dl, pl, d))
    A("")
    A("Total session claim: device=%d, python=%d, gap=%+d.\n" % (
        dev_len["session"], py_len["session"],
        py_len["session"] - dev_len["session"]))
    A("## 5. Corrected profile reproduces\n")
    A("Using the device's own param set, `build_desc10` gives: session=%d, "
      "click=%d, attribution=%d.\n" % (
          corr_len["session"], corr_len["click"], corr_len["attribution"]))
    A("## 6. CTIT\n")
    A("- click_time -> installed_at = %.3f s (%.2f min)" % (ctit, ctit / 60.0))
    A("- click_time -> install_begin_time = %.3f s" % ctit_ib)
    with open(os.path.join(HERE, "PARAM_DIFF.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
