import json, struct, sys, re, time
sys.path.insert(0, r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev')
HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
from fin_vm2 import FinEx

c = json.load(open(HERE + '/corpus.json'))
SI, BLOBS, HS = c['sign_inputs'], c['blobs'], c['hs']

FIELDS = ['adj_verification', 'android_uuid', 'api_level', 'app_token',
          'app_version', 'created_at', 'device_name', 'device_type',
          'environment', 'gps_adid', 'gps_adid_src', 'os_build',
          'store_name_from_system', 'installed_at', 'os_build', 'os_name',
          'os_version', 'package_name', 'adj_signing_id', 'ui_mode',
          'initiating_package_name', 'session_count', 'updated_at',
          'activity_kind', 'client_sdk', 'headers_id', 'native_version']

CONST = {'adj_verification': 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
         'adj_signing_id': '1500000', 'client_sdk': 'android5.7.0',
         'headers_id': '10', 'native_version': '5.0.0'}


def parse_map(s):
    body = s.strip()
    if body.startswith('{') and body.endswith('}'):
        body = body[1:-1]
    out = []
    for tok in body.split(', '):
        if '=' in tok:
            k, v = tok.split('=', 1)
            out.append((k, v))
    return out


def nearest(lst, ts, key='ts', win=8000):
    best, bt = None, None
    for e in lst:
        d = abs(e[key] - ts)
        if bt is None or d < bt:
            best, bt = e, d
    return (best, bt) if bt is not None and bt <= win else (None, None)


def build10(mp):
    d = dict(mp)
    for k, v in CONST.items():
        d.setdefault(k, v)
    vals = []
    for f in FIELDS:
        v = d.get(f)
        if v is None:
            return None, f
        vals.append(v)
    return ''.join(vals).encode(), None


def run_blob(blob_hex, H_hex, sec, packed):
    D = json.load(open(HERE + '/fin_descs.json'))
    by = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex']))
          for d in D['descs']}
    by[10] = (len(packed) // 4, packed)
    by[4] = (8, bytes.fromhex(H_hex))
    # #0: KEEP the template's real telemetry record. sens_test proved #0
    # affects 44/48 body dwords, so zeroing it forces a 44/44 mismatch and
    # invalidates the test (that flaw produced the earlier NOT-PROVEN run).
    # Rationale: corpus signings and the template are the same moto install,
    # and #0 is per-install environment telemetry (expected stable).
    ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
    seq = [(by[i][0], 0, by[i][1]) for i in ORDER]
    ex = FinEx(sec, seq)
    st = ex.run(max_steps=20_000_000)
    sinks = {}
    for (s, n, v) in ex.emit_trace:
        sinks.setdefault(s, {})[n] = v
    blob = b''.join(struct.pack('>I', sinks[0x5500000000].get(i, 0))
                    for i in range(48))
    raw = bytes.fromhex(blob_hex)
    dw = lambda b, i: struct.unpack('>I', b[i * 4:i * 4 + 4])[0]
    diffs = [i for i in range(48) if dw(blob, i) != dw(raw, i)]
    return st, blob[:16] == raw[:16], diffs


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'survey'
    if mode == 'survey':
        print('sign_inputs:', len(SI), ' blobs:', len(BLOBS), ' hs:', len(HS))
        for b in BLOBS:
            si, ds = nearest(SI, b['ts'])
            h, dh = nearest(HS, b['ts'])
            kind = ''
            if si:
                m = parse_map(si['map_toString'])
                kd = dict(m).get('activity_kind', '?')
                sc = dict(m).get('session_count', '-')
                kind = f'{kd} sc={sc} fields={len(m)}'
            print(f"blob ts={b['ts']} -> si d={ds} ({kind})  H d={dh}")
        m0 = parse_map(SI[0]['map_toString'])
        print('map fields:', [k for k, _ in m0])
    else:  # verify mode: blob index list
        for idx in [int(x) for x in sys.argv[2].split(',')]:
            b = BLOBS[idx]
            si, ds = nearest(SI, b['ts'])
            h, dh = nearest(HS, b['ts'])
            if si is None or h is None:
                print(f'blob[{idx}]: no pair si={ds} h={dh}')
                continue
            mp = parse_map(si['map_toString'])
            packed, miss = build10(mp)
            if packed is None:
                print(f'blob[{idx}]: missing field {miss}')
                continue
            print(f'blob[{idx}] kind={dict(mp).get("activity_kind")} '
                  f'packedLen={len(packed)} (dw7={len(packed)//4}) H=..{h["H"][:8]} '
                  f'si_d={ds} h_d={dh}', flush=True)
            t0 = time.time()
            st, hok, diffs = run_blob(b['hex'], h['H'], b['ts'] // 1000, packed)
            print(f'  -> status={st} hdrMatch={hok} bodyDiff={len(diffs)}/44 '
                  f'({time.time()-t0:.0f}s) diffs={diffs[:8]}', flush=True)


