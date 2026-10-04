# desc10_law.py - the PROVEN unified desc10 law (slice 96): byte-exact for
# session + click vs the device's own captures. Shared by law tests and forge.
#   desc10 = sorted(profile claims A-Z) + adj_signing_id (pinned)
#          + sorted(session claims A-Z)
#          + [activity_kind, client_sdk, headers_id, native_version]
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

PROFILE_COMMON = [
    'adj_verification', 'android_uuid', 'api_level', 'app_token', 'app_version',
    'created_at', 'device_name', 'device_type', 'environment', 'gps_adid',
    'gps_adid_src', 'hardware_name', 'installed_at', 'os_build', 'os_name',
    'os_version', 'package_name',
]
# Optional profile claims. `push_token` was found in the 504 B / 532 B captures
# (slice 105): a 143-char FCM token appended to the profile set, i.e. it simply
# sorts between `package_name` and `referrer`. It is present only when the app
# has a token, which is exactly why the 360/387 B captures lack it.
OPTIONAL_PROFILE = ['push_token']
SESSION_PROFILE = ['initiating_package_name']
CLICK_PROFILE = ['google_play_instant', 'referrer', 'referrer_api']
SESSION_TAIL = ['session_count', 'store_name_from_system', 'tracking_enabled',
                'updated_at']
CLICK_TAIL = ['session_count', 'session_length', 'source', 'subsession_count',
              'time_spent', 'tracking_enabled', 'updated_at']
BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']
PINNED = 'adj_signing_id'

# ---------------------------------------------------------------------------
# ATTRIBUTION kind - derived from the device's OWN attribution map
# (device/gold6.json idx 2/5, activity_kind="attribution", 30 map keys), NOT yet
# byte-verified against a captured desc10 because no EMIT trace contains an
# attribution signing. Status: PREDICTED, with a testable signature:
#   prediction = 21 values, unpadded 246 B -> descriptor #10 of 248 B (62 dwords),
#   a length that does NOT occur among the captured 360/388/504/532 B sessions and
#   clicks. One device EMIT capture of an attribution signing confirms or refutes it.
#
# Rationale: the attribution map carries 14 of PROFILE_COMMON's 17 keys (missing
# hardware_name / installed_at / os_build, which are install-time facts a poll does
# not carry) plus `initiated_by` (which IS payload-bearing per slice 99 §8.2 and is
# present in every attribution map), and exactly one tail key (tracking_enabled).
# ---------------------------------------------------------------------------
ATTRIBUTION_PROFILE = [k for k in PROFILE_COMMON
                       if k not in ('hardware_name', 'installed_at', 'os_build')]
ATTRIBUTION_PROFILE += ['initiated_by']
ATTRIBUTION_TAIL = ['tracking_enabled']


def desc10_keys(kind, val=None):
    """Emission key order for one activity kind.

    Optional profile claims (currently `push_token`) are included only when the
    caller's map actually carries them - matching the device captures.
    """
    if kind == 'session':
        profile = PROFILE_COMMON + SESSION_PROFILE
        tail = SESSION_TAIL
    elif kind == 'click':
        profile = PROFILE_COMMON + CLICK_PROFILE
        tail = CLICK_TAIL
    elif kind == 'attribution':
        profile = list(ATTRIBUTION_PROFILE)
        tail = list(ATTRIBUTION_TAIL)
    else:
        raise ValueError('desc10 law known for kinds: session, click, attribution '
                         '(got %r)' % kind)
    profile = list(profile)
    for k in OPTIONAL_PROFILE:
        if val and k in val and val[k] not in (None, ''):
            profile.append(k)
    return sorted(profile) + [PINNED] + sorted(tail) + BLOCK2


def pad4(b):
    """The native pads desc10 with NULs up to a 4-byte multiple (slice 105:
    503->504 session+token, 530->532 click+token, 387->388 click)."""
    if isinstance(b, str):
        return b + '\0' * (-len(b) % 4)
    return b + b'\0' * (-len(b) % 4)


def build_desc10(val, kind):
    """val: dict key->string value (all law keys must be present, non-empty).
    Returns the exact byte string the native packs into descriptor #10."""
    keys = desc10_keys(kind, val)
    missing = [k for k in keys if k not in val or val[k] in (None, '')]
    if missing:
        raise KeyError('desc10 law missing values: %s' % missing)
    return ''.join(val[k] for k in keys)


def self_test():
    """Replay BOTH device captures; assert byte-exact (the slice-96 proof)."""
    ok = True
    # session: golden 360 B from fin_descs + wh4 si[7]
    W = json.load(open(os.path.join(HERE, 'wh4_records.json'), encoding='utf-8'))
    F = json.load(open(os.path.join(HERE, 'fin_descs.json'), encoding='utf-8'))
    d10 = bytes.fromhex([d for d in F['descs'] if d['build_idx'] == 10][0]['data_hex'])\
        .decode('latin1')
    si = W['sign_inputs'][W['golden_sign_input_idx']]
    sval = {}
    for part in si['order'].split('\x02'):
        if '\x01' in part:
            k, v = part.split('\x01', 1)
            sval[k] = v
    got = build_desc10(sval, 'session')
    print('session: %d B  %s' % (len(got), 'BYTE-EXACT' if got == d10 else 'FAIL'))
    ok &= got == d10
    # click: captured 387 B run + its own toString map (wh4 line 286234)
    import re
    with open(os.path.join(os.path.dirname(HERE), 'device', 'adj9_wh4.log'),
              encoding='utf-8', errors='replace') as f:
        for ln, line in enumerate(f, 1):
            if ln == 286234:
                m = re.search(r'\{(.*)\}', line.strip())
                cval = dict(re.findall(
                    r'([A-Za-z0-9_]+)=([^,]*(?:\([^)]*\)[^,]*)*), ?', m.group(1) + ','))
                break
    cval.setdefault('adj_signing_id', '1500000')
    cval.setdefault('headers_id', '10')
    cval.setdefault('native_version', '5.0.0')
    click = json.load(open(os.path.join(HERE, 'desc10_runs.json'),
                           encoding='utf-8'))['click']
    gotc = build_desc10(cval, 'click')
    print('click:   %d B  %s' % (len(gotc), 'BYTE-EXACT' if gotc == click else 'FAIL'))
    ok &= gotc == click
    return ok


if __name__ == '__main__':
    raise SystemExit(0 if self_test() else 1)
