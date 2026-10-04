"""_row8probe.py — is the click-row8 divergence the REGION or our desc10?

Uses the DEVICE's own d0/d2/d4/d8/d9/d7 (stored in all_signings.json) and
substitutes OUR desc10 (proven byte-exact vs the genuine d10).  If the click
then reproduces over the recovered seconds, the claims are right and only the
region/second was wrong.  If it still fails, the DEVICE's d10 differs from
ours despite the same length.
"""
import binascii, json, multiprocessing as mp, os, struct, sys
sys.path.insert(0, '.')
import mint_pipeline as M

HERE = os.path.dirname(os.path.abspath(__file__))
BLOBS = os.path.join(HERE, '_genuine_blobs.json')
SECS = os.path.join(HERE, '_blob_seconds.json')
_G = {}

def _init(descs, d10):
    import mint_pipeline as m
    _G['m'] = m
    _G['blobs'] = set(json.load(open(BLOBS)))
    _G['descs'] = descs
    _G['d10'] = d10

def _try(sec):
    by = dict(_G['descs'])
    by[10] = (len(_G['d10']) // 4, _G['d10'])
    descs = [by[i] for i in M.VA_ORDER]
    try:
        blob, vm = _G['m'].finex_mint(descs, sec)
    except Exception:
        return None
    h = blob.hex()
    return (sec, h) if h in _G['blobs'] else None

def main():
    sig = json.load(open(os.path.join(HERE, 'all_signings.json')))
    r8 = [r for r in sig if r['ev'] == 22272][0]
    gen_d10 = binascii.unhexlify(r8['d10']).rstrip(b'\x00')
    # our desc10 built from the CORRECT uuid (37-char variant verified below)
    sys.path.insert(0, HERE)
    import subprocess
    # rebuild our desc10 via claims_for_law
    vals = {
     'adj_verification':'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
     'android_uuid':'d773f47f-fc0e-4994-9cf7-7c3cf5bb6368','api_level':'31',
     'app_token':'jut9tib0eeps','app_version':'3.13.9',
     'created_at':'2026-09-12T21:15:11.762Z+0200','device_name':'moto g42',
     'device_type':'phone','environment':'production','google_play_instant':'0',
     'gps_adid':'f476b3d4-e0b1-4707-bc43-6153d17f7f8c','gps_adid_src':'service',
     'hardware_name':'S2SE32.28-28-4','installed_at':'2026-09-08T12:20:49.782Z+0200',
     'os_build':'S2SE32.28-28-4','os_name':'android','os_version':'12',
     'package_name':'com.penti.app','referrer':'utm_source=google-play&utm_medium=organic',
     'referrer_api':'google','adj_signing_id':'1500000','session_count':'1',
     'session_length':'0','source':'install_referrer','subsession_count':'1',
     'time_spent':'0','tracking_enabled':'1',
     'updated_at':'2026-09-10T07:26:18.015Z+0200','activity_kind':'click',
     'client_sdk':'android5.7.0','headers_id':'10','native_version':'5.0.0'}
    padded, unpadded = M.claims_for_law(vals, 'click')
    our_d10 = padded
    print('our desc10 len=%d  genuine d10 len=%d  identical=%s'
          % (len(our_d10), len(gen_d10), our_d10 == gen_d10))
    d0 = binascii.unhexlify(r8['d0']); d2 = binascii.unhexlify(r8['d2'])
    d4 = binascii.unhexlify(r8['d4']); d8 = binascii.unhexlify(r8['d8'])
    d9 = binascii.unhexlify(r8['d9']); d7 = int(r8['d7'], 16)
    descs = {0:(36,d0),9:(5,d9),8:(4,d8),4:(8,d4),2:(1,d2),
             7:(1,struct.pack('>I',d7)),10:(0,b''),5:(1,b'\0'*4),
             6:(1,b'\0'*4),1:(0,b''),3:(0,b'')}
    secs = sorted(set(json.load(open(SECS)).values()))
    print('sweeping %d seconds with DEVICE descriptors + OUR desc10' % len(secs))
    hit = None
    with mp.Pool(14, initializer=_init, initargs=(descs, our_d10)) as pool:
        for res in pool.imap_unordered(_try, secs, chunksize=1):
            if res:
                hit = res; pool.terminate(); break
    if hit:
        print('*** ROW8 REPRODUCES with our desc10: second=%d' % hit[0])
    else:
        print('*** ROW8 STILL FAILS with our desc10 -> the DEVICE d10 content')
        print('    differs from ours (same length, different bytes) OR the')
        print('    region/second is unrecoverable for this row.')

if __name__ == '__main__':
    main()
