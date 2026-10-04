"""verify_pure.py — the gate for adj9_pure.py.

Two independent checks:

  1. adj9_pure.sign_request == adj9_signature.sign_request_vm  192/192,
     on the same descriptor plane, for session / click / attribution.
     This is the authoritative one: the FinEx VM is the ground truth.
  2. adj9_pure rebuilds all six genuine penti captures from scratch, 192/192,
     with no VM involved at all.

Run:  python verify_pure.py [app_name]
"""
import base64
import json
import os
import re
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj9_decode as D  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

KINDS = ("session", "click", "attribution")


def gate_vm(app_name):
    print("=" * 68)
    print("GATE 1  adj9_pure  vs  the FinEx VM  (%s)" % app_name)
    print("=" * 68)
    import adj9_pure as P
    import adj9_signature as S          # the VM lives here
    dev = json.load(open(os.path.join(HERE, "device_data.json")))
    camp = json.load(open(os.path.join(HERE, "apps.json")))[app_name]
    S.configure_app(camp)          # only the VM reference needs this
    P.campaign_data = camp         # our signer now reads the global
    gaid, auid = str(uuid.uuid4()), str(uuid.uuid4())
    sec, seed = 1790341508, 0xDEADBEEF
    # Both signers must be given the SAME head phase, or they are signing
    # different records and the comparison is meaningless.  The phase does
    # affect the bytes (just not the attribution).
    head = P.HEAD_PHASE_DEFAULT
    # a minimal, internally consistent field map: both signers must see the
    # SAME map, the comparison is about the crypto, not the body shape
    base_f = {"app_token": camp["app_token"],
              "package_name": camp["package_name"],
              "app_version": camp.get("app_version", "3.13.9"),
              "gps_adid": gaid, "android_uuid": auid,
              "environment": "production", "device_type": "phone",
              "gps_adid_src": "service", "gps_adid_attempt": "1",
              "foreground": "1", "needs_response_details": "1",
              "attribution_deeplink": "1", "offline_mode_enabled": "0",
              "ui_mode": "1", "tracking_enabled": "1", "os_name": "android",
              "os_version": dev.get("os_version", "12"),
              "api_level": dev.get("api_level", "31"),
              "device_name": dev.get("device_name", ""),
              "os_build": dev.get("os_build", ""),
              "hardware_name": dev.get("hardware_name", ""),
              "language": dev.get("language", ""),
              "created_at": "2026-10-03T10:00:00.000Z+0000",
              "sent_at": "2026-10-03T10:00:01.000Z+0000"}
    extra = {
        "session": {"country": dev.get("country", ""),
                    "session_count": "1",
                    "installed_at": "2026-10-03T10:00:02.000Z+0000",
                    "updated_at": "2026-10-03T10:00:02.000Z+0000",
                    "store_name_from_system": "com.android.vending",
                    "initiating_package_name": "com.android.vending"},
        "click": {"country": dev.get("country", ""),
                  "click_time": "2026-10-03T09:59:46.000Z+0000",
                  "click_time_server": "2026-10-03T09:59:47.000Z+0000",
                  "install_begin_time": "2026-10-03T09:59:54.000Z+0000",
                  "install_begin_time_server": "2026-10-03T09:59:55.000Z+0000",
                  "installed_at": "2026-10-03T10:00:02.000Z+0000",
                  "updated_at": "2026-10-03T10:00:02.000Z+0000",
                  "source": "install_referrer", "referrer_api": "google",
                  "referrer": "adjust_reftag=TESTREFTAG",
                  "google_play_instant": "0",
                  "install_version": camp.get("app_version", "3.13.9"),
                  "session_count": "1", "session_length": "0",
                  "subsession_count": "1", "time_spent": "0"},
        "attribution": {"initiated_by": "backend"},
    }
    ok = tot = 0
    for kind in KINDS:
        f = dict(base_f, **extra[kind])
        t0 = time.perf_counter()
        auth = P.sign_request(f, kind, head=head, second=sec, seed=seed)
        pure = base64.b64decode(
            re.search(r'signature="([^"]+)"', auth).group(1))
        t_pure = time.perf_counter() - t0
        t0 = time.perf_counter()
        vm, _s, _i = S.sign_request_vm(f, kind, head=head, second=sec, seed=seed)
        t_vm = time.perf_counter() - t0
        m = sum(a == b for a, b in zip(pure, vm))
        ok += m == 192
        tot += 1
        print("  %-12s %3d/192 %-8s  pure %5.0f ms   vm %5.1f s"
              % (kind, m, "EXACT" if m == 192 else "MISMATCH",
                 t_pure * 1000, t_vm))
        if m != 192:
            i = next(k for k, (a, b) in enumerate(zip(pure, vm)) if a != b)
            print("      first diff at byte %d" % i)
    print("  -> %d/%d\n" % (ok, tot))
    return ok == tot


def gate_genuine():
    print("=" * 68)
    print("GATE 2  adj9_pure rebuilds the 6 genuine captures (no VM)")
    print("=" * 68)
    import adj9_pure as P
    import itertools
    log = os.path.join(HERE, "..", "adj9", "rev", "win_capture",
                       "module_win_capture.log")
    lines = open(log, encoding="utf-8", errors="replace").read().split("\n")
    si = [i for i, l in enumerate(lines)
          if l.startswith("###ADJ9_BEGIN type=sign_input")]
    ah = [i for i, l in enumerate(lines)
          if l.startswith("###ADJ9_BEGIN type=authorization_header")]
    # the captures are penti, and carry BOTH head phases -- so recover the
    # seed, the cert and the phase from each blob instead of assuming them
    base = json.load(open(os.path.join(HERE, "apps.json")))["penti"]
    ok = tot = 0
    for n, (i, j) in enumerate(zip(si, ah)):
        v = {}
        for k in range(i, i + 10):
            if lines[k].startswith("map_order="):
                for p in lines[k][len("map_order="):].split("\x02"):
                    if "\x01" in p:
                        kk, vv = p.split("\x01", 1)
                        v[kk] = vv
                break
        blob = base64.b64decode(
            re.search(r'signature="([A-Za-z0-9+/=]+)"', lines[j + 2]).group(1))
        ts = int(re.search(r"ts=(\d{13})", lines[i]).group(1)) // 1000
        rec = D.whiten_body_inverse(blob[16:160], blob[:16])
        seed = int.from_bytes(rec[20:24], "big")
        cert, head = rec[25:45], rec[3:19]
        # search for the phase that regenerates this head from this seed
        phase = None
        for k in (1, 2, 3):
            for ph in itertools.permutations(range(0x20, 0x50), k):
                try:
                    if P.head16_for(seed, ph) == head:
                        phase = ph
                        break
                except Exception:
                    continue
            if phase:
                break
        camp = dict(base, cert_sha1=cert.hex())   # the capture's own cert
        P.campaign_data = camp
        kind = v.get("activity_kind", "session")
        best = 0
        # the captures span BOTH claim laws (5.7 and 5.8) -- try each
        for law in (P.claims_padded_58, P.claims_padded):
            saved_law = P.claims_padded
            P.claims_padded = law
            try:
                auth = P.sign_request(v, kind, head=phase,
                                      second=ts, seed=seed)
                got = base64.b64decode(
                    re.search(r'signature="([^"]+)"', auth).group(1))
                best = max(best, sum(a == b for a, b in zip(got, blob)))
            except Exception as exc:          # noqa: BLE001
                print("      law %s raised %s" % (law.__name__, exc))
            P.claims_padded = saved_law
        ok += best == 192
        tot += 1
        print("  win%d  %3d/192 %-9s seed=%08x phase=%s"
              % (n, best, "EXACT" if best == 192 else "MISMATCH", seed, phase))
    print("  -> %d/%d\n" % (ok, tot))
    return ok == tot


def main():
    app = sys.argv[1] if len(sys.argv) > 1 else "creditsea"
    a = gate_vm(app)
    b = gate_genuine()
    print("RESULT: %s" % ("ALL GATES PASS" if (a and b) else "FAILED"))
    return 0 if (a and b) else 1


if __name__ == "__main__":
    sys.exit(main())