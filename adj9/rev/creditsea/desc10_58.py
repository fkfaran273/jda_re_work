"""desc10_58.py — the PROVEN Adjust Signature 5.8.0 claims law (descriptor #10),
byte-exact against three genuine com.creditsea.app device signings (session,
click, attribution; n=0/192 differing bytes each, see SOLVED.md).

Interface mirrors adj9/rev/desc10_law.py:
    build_desc10_58(val, kind)           -> the exact #10 byte string
    claims_for_law_58(val, kind)         -> (padded #10 bytes, unpadded length)
    desc10_keys_58(val, kind)            -> emission key order (law, filtered)

THE LAW (values only, no keys, no separators; NUL-padded to a 4-byte multiple
for the descriptor, #7 keeps the UNPADDED length):

    #10 = sorted(<profile keys present>  A..Z, VALUES only)
        + '1500000'                                   (adj_signing_id, pinned)
        + sorted(<tail keys present>     A..Z, VALUES only)
        + activity_kind + client_sdk + '10' + '5.0.0'  (block2, in this order)

5.8.0 key lists (the 5.7.0/penti lists EXTENDED - this is the entire 5.8.0
delta, proven by the three byte-exact mints):

  profile base (all kinds)     adj_verification android_uuid api_level
                               app_token app_version created_at device_name
                               device_type environment gps_adid gps_adid_src
                               hardware_name installed_at os_build os_name
                               os_version package_name
  session profile  +           country initiating_package_name
  click profile    +           country click_time click_time_server
                               google_play_instant install_begin_time
                               install_begin_time_server install_version
                               referrer referrer_api
  attribution profile          base MINUS hardware_name installed_at os_build
                               PLUS initiated_by
  session tail                 session_count session_length
                               store_name_from_system subsession_count
                               time_spent tracking_enabled updated_at
  click tail                   session_count session_length source
                               subsession_count time_spent tracking_enabled
                               updated_at
  attribution tail             tracking_enabled
  block2 (all kinds)           activity_kind client_sdk headers_id native_version

Presence rule: a law key enters only when the caller's map actually carries it
(non-empty).  The pinned adj_signing_id/headers_id/native_version values are
emitted even though the native never READS them from the map (pinned
constants; proven by the LSPosed mapget trace in adj9_cap_fresh.log).

Session tail is 7 keys: the LSPosed mapget trace in adj9_cap_full.log
(session signing ts=1790741166994) shows the native's claims pass reads 28
sorted keys regardless of presence - session_length/subsession_count/
time_spent included, twice each (length pass + pack pass).  The fresh-capture
session packet (adj9_cap_fresh.log) simply did not CARRY those three keys, so
the presence rule skipped them there; the 2026-09-30 session packet does carry
them (session_length=2462 subsession_count=4 time_spent=1154) and mints
byte-exact only with the 7-key tail.
"""
import hashlib
import os

HERE = os.path.dirname(os.path.abspath(__file__))

PROFILE_BASE = [
    'adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
    'created_at', 'device_name', 'device_type', 'environment', 'gps_adid',
    'gps_adid_src', 'hardware_name', 'installed_at', 'os_build', 'os_name',
    'os_version', 'package_name',
]
SESSION_EXTRA = ['country', 'initiating_package_name']
CLICK_EXTRA = ['click_time', 'click_time_server', 'country',
               'google_play_instant', 'install_begin_time',
               'install_begin_time_server', 'install_version', 'referrer',
               'referrer_api']
ATTR_DROP = ['hardware_name', 'installed_at', 'os_build']
ATTR_EXTRA = ['initiated_by']
SESSION_TAIL = ['session_count', 'session_length', 'store_name_from_system',
                'subsession_count', 'time_spent', 'tracking_enabled',
                'updated_at']
CLICK_TAIL = ['session_count', 'session_length', 'source', 'subsession_count',
              'time_spent', 'tracking_enabled', 'updated_at']
ATTR_TAIL = ['tracking_enabled']
BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']
PIN = 'adj_signing_id'
PIN_DEFAULT = '1500000'

# Genuine validation vectors (com.creditsea.app, moto g42, 2026-09-29,
# adj9_cap_fresh.log): sha256 of the UNPADDED #10 claims string per signing,
# with the signing second and the genuine 192-B blob.
GOLD = [
    {"kind": "session", "second": 1790694158, "unpadded_len": 380,
     "claims_sha256": "249f385041c4007b185c7ff2531269418eb7b8ab25b2b234713d9058d3a7452e",
     "blob_hex": "26148db92c7134c438f3b3d7219b36841e08eab70fdabe6417ef02699c35d055d3f45c03d69cdc9db912b0e49fe2d1289bfa5005d861c8953a90c613d0eddd6fc6477e5d947fc6c4a5684d9ea0b191dac317f1142982fdd4c23c1cfd0c68b0578179f15fa1f5cb99fe9618d9a4b43c63c061fb3ea1098b1d331f543f3f80981e13fa314b3a922ec74010d0452a3f35bec0428ace2c4602e669f777a429bc845c18bbb292ac2eb866bdbbf6193af2743650a77bb3be45499d5b793aeb598e7fc7"},
    {"kind": "click", "second": 1790694159, "unpadded_len": 516,
     "claims_sha256": "ff32b385605ad206e87335394051126bda5c8b3dcfa09b2b9b968a15719f85c5",
     "blob_hex": "1324ef343e3d350b0ddf4f523fce48b347ee7dd4c886a9e4d1aaa672042420ad9fd7adce1e4bcb444fbd73938b8a70bee667e599eb9a38d8fc99d0772141ce88fdba16d9e4a8b95a47b2585daec2953f5a2ddf6eec8e033179e467f3cd8d6f45d5262fa68e771fbea8c137f659d89991864766e2a1efb939903eeee7780a5707e95c76f938233f74ce0810f3f1aced1c98e4614d30fdc19e79672d625a87c39a7a44bea389fd01a48fe61b08cee6377bfdefcd42a293367f70bb3eaa47ac1550"},
    {"kind": "attribution", "second": 1790694166, "unpadded_len": 264,
     "claims_sha256": "28bf37c57aa9bf555fb47af1fff2ff790e320d92cdb6ef1abb26a8578227e37e",
     "blob_hex": "23d5723505a22701424476ae2658a46561a634a2fb5827b1e3e80134e24f7c26686c6a88e8c3be3f769b4faa56f8920127426ba606a561970c241525a74365e13888b29f661203be3a2bec8f068f5042afe801faa97b7e6f48edea909a4f6f1dc97a41a5e3c807cf2d19adee7407e3b5d155d8fb9753ad29f29a53ce51e04eeb33a2e487f825f0733b8edf2867c23b3628188b64c5521e927562a180ce6a6a5a4ab31043f17660428badf14d9a643c8cd0b8cab028a12e3abdc5307709731ebf"},
]


def _lists(kind):
    if kind == 'session':
        return PROFILE_BASE + SESSION_EXTRA, SESSION_TAIL
    if kind == 'click':
        return PROFILE_BASE + CLICK_EXTRA, CLICK_TAIL
    if kind == 'attribution':
        return [k for k in PROFILE_BASE if k not in ATTR_DROP] + ATTR_EXTRA, ATTR_TAIL
    raise ValueError('desc10_58 law known for kinds: session, click, attribution '
                     '(got %r)' % kind)


def desc10_keys_58(val, kind):
    """Emission key order for one activity kind (law keys present in `val`)."""
    profile, tail = _lists(kind)
    keys = [k for k in sorted(profile) if val.get(k)]
    keys.append(PIN)                      # emitted pinned; read or not
    keys += [k for k in sorted(tail) if val.get(k)]
    keys += [k for k in BLOCK2 if val.get(k)]
    return keys


def build_desc10_58(val, kind):
    """val: dict key->string.  Returns the EXACT byte string the 5.8.0 native
    packs into descriptor #10 (unpadded)."""
    keys = desc10_keys_58(val, kind)
    missing = [k for k in keys if not val.get(k)]
    if missing:
        raise KeyError('desc10_58 law missing values: %s' % missing)
    return ''.join(val[k] for k in keys).encode('latin1')


def claims_for_law_58(val, kind):
    """(padded #10 bytes, unpadded length) - NUL-pad to a 4-byte multiple;
    descriptor #7 carries the UNPADDED length."""
    raw = build_desc10_58(val, kind)
    return raw + b"\x00" * (-len(raw) % 4), len(raw)


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def self_test():
    """Check the law strings against the captured-signing sha256 vectors."""
    import json
    ok = True
    valmaps = _gold_maps()
    for g in GOLD:
        val = valmaps[g['kind']]
        raw = build_desc10_58(val, g['kind'])
        sha = hashlib.sha256(raw).hexdigest()
        good = (len(raw) == g['unpadded_len'] and sha == g['claims_sha256'])
        print('%-11s len=%3d (want %3d)  sha %s  %s'
              % (g['kind'], len(raw), g['unpadded_len'], sha[:16] + '...',
                 'OK' if good else 'FAIL'))
        ok &= good
    return ok


def validate_against_device(max_steps=60_000_000):
    """Full-stack check: rebuild the descriptor plane per signing, drive the
    FinEx VM, and require the minted 192-B blob == the genuine device blob."""
    import sys
    sys.path.insert(0, os.path.dirname(HERE))
    from testbed import mine_log, decode, region_parts, run_vm, build_descs
    ok = True
    for s in mine_log():
        kind = s['val'].get('activity_kind', 'session')
        dec = decode(s['blob'])
        d0, d4, d2, pfx = region_parts(dec, s['second'])
        raw, padded = claims_for_law_58(s['val'], kind)
        blob, status = run_vm(s['second'],
                              build_descs(s['second'], raw, d0, d4, d2),
                              max_steps=max_steps)
        good = blob == s['blob']
        print('%-11s second=%d  %d/192 bytes match  %s'
              % (kind, s['second'],
                 192 - sum(1 for i in range(192) if blob[i] != s['blob'][i]),
                 'BYTE-EXACT' if good else 'FAIL'))
        ok &= good
    return ok


def _gold_maps():
    """The three captured claims maps, mined from adj9_cap_fresh.log."""
    sys_path_add = os.path.dirname(HERE)
    import sys
    if sys_path_add not in sys.path:
        sys.path.insert(0, sys_path_add)
    from testbed import mine_log
    out = {}
    for s in mine_log():
        out[s['val'].get('activity_kind', 'session')] = s['val']
    return out


if __name__ == '__main__':
    import sys
    if '--vm' in sys.argv:
        ok = validate_against_device()
    else:
        ok = self_test()
    raise SystemExit(0 if ok else 1)
