"""law58.py — targeted 5.8.0 claims-law candidates for the session/click blobs.

Built from the LSPosed mapget evidence: the native reads exactly
  sorted(law keys present in the map) with activity_kind+client_sdk last,
  plus pinned constants adj_signing_id/headers_id/native_version that are
  NOT read.  The attribution signing already minted BYTE-EXACT with the penti
  law, so the layout is: sorted(profile vals) + '1500000' + sorted(tail vals)
  + [activity_kind, client_sdk, '10', '5.0.0']  (values only, no separators).
  The only open question is WHICH keys the 5.8.0 profile/tail lists carry.
"""
import sys, os, struct, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from testbed import mine_log, decode, region_parts, run_vm, build_descs

D9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")

PROFILE_BASE = ['adj_verification', 'android_uuid', 'api_level', 'app_token',
                'app_version', 'created_at', 'device_name', 'device_type',
                'environment', 'gps_adid', 'gps_adid_src', 'hardware_name',
                'installed_at', 'os_build', 'os_name', 'os_version',
                'package_name']
SESSION_PROFILE = PROFILE_BASE + ['country', 'initiating_package_name']
SESSION_TAIL = ['session_count', 'store_name_from_system', 'tracking_enabled',
                'updated_at']
CLICK_PROFILE = PROFILE_BASE + ['click_time', 'click_time_server', 'country',
                                'google_play_instant', 'install_begin_time',
                                'install_begin_time_server', 'install_version',
                                'referrer', 'referrer_api']
CLICK_TAIL = ['session_count', 'session_length', 'source', 'subsession_count',
              'time_spent', 'tracking_enabled', 'updated_at']
ATTR_PROFILE = [k for k in PROFILE_BASE
                if k not in ('hardware_name', 'installed_at', 'os_build')]
ATTR_PROFILE += ['initiated_by']
ATTR_TAIL = ['tracking_enabled']
BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']
PIN = 'adj_signing_id'


def law58(val, profile, tail, pin=PIN, block2=BLOCK2):
    keys = [k for k in sorted(profile) if k in val] \
         + [pin if pin in val or True else None] \
         + [k for k in sorted(tail) if k in val] \
         + [k for k in block2 if k in val]
    vals = [val[k] for k in sorted(profile) if k in val]
    if pin:
        vals.append(val.get(pin, '1500000'))
    vals += [val[k] for k in sorted(tail) if k in val]
    vals += [val[k] for k in block2 if k in val]
    return ''.join(vals).encode('latin1')


def variants(val):
    kind = val.get('activity_kind', 'session')
    out = {}
    if kind == 'session':
        out['L1_profile+country'] = law58(val, SESSION_PROFILE, SESSION_TAIL)
        out['L2_nocountry'] = law58(val, PROFILE_BASE + ['initiating_package_name'],
                                    SESSION_TAIL)
        out['L3_nopin'] = law58(val, SESSION_PROFILE, SESSION_TAIL, pin=None)
        out['L4_noblock2consts'] = law58(val, SESSION_PROFILE, SESSION_TAIL,
                                         block2=['activity_kind', 'client_sdk'])
        out['L5_country_in_tail'] = law58(val, PROFILE_BASE + ['initiating_package_name'],
                                          SESSION_TAIL + ['country'])
        out['L6_pin_first'] = (val.get('adj_signing_id', '1500000').encode() +
                               law58(val, SESSION_PROFILE, SESSION_TAIL, pin=None))
    elif kind == 'click':
        out['L1_profile+country+clickkeys'] = law58(val, CLICK_PROFILE, CLICK_TAIL)
        out['L2_nocountry'] = law58(val, PROFILE_BASE + [
            'click_time', 'click_time_server', 'google_play_instant',
            'install_begin_time', 'install_begin_time_server', 'install_version',
            'referrer', 'referrer_api'], CLICK_TAIL)
        out['L3_nopin'] = law58(val, CLICK_PROFILE, CLICK_TAIL, pin=None)
        out['L4_noblock2consts'] = law58(val, CLICK_PROFILE, CLICK_TAIL,
                                         block2=['activity_kind', 'client_sdk'])
    elif kind == 'attribution':
        out['L1_penti_attr'] = law58(val, ATTR_PROFILE, ATTR_TAIL)
    return out


def main():
    sigs = mine_log()
    only = [int(x) for x in sys.argv[1:]] or list(range(len(sigs)))
    wins = []
    for si in only:
        s = sigs[si]
        kind = s['val'].get('activity_kind')
        dec = decode(s['blob'])
        d0, d4, d2, pfx = region_parts(dec, s['second'])
        print(f"=== signing {si} {kind} second={s['second']}")
        for name, raw in variants(s['val']).items():
            blob, status = run_vm(s['second'], build_descs(s['second'], raw, d0, d4, d2))
            if blob is None:
                print(f"  {name:30s} len={len(raw):4d} NO SINK"); continue
            exact = blob == s['blob']
            if exact:
                wins.append((si, name, len(raw)))
            print(f"  {name:30s} len={len(raw):4d} {status:10s} "
                  + ("BYTE-EXACT ***" if exact else
                     f"ndiff={sum(1 for i in range(192) if blob[i]!=s['blob'][i])}"))
    print("\nWINS:", wins or "none")


if __name__ == '__main__':
    main()
