import os, sys, re, urllib.parse
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7_pure as A

def load(folder, n):
    p = os.path.join(HERE, folder, '%02d_c.txt' % n)
    t = open(p, encoding='utf-8', errors='replace', newline='').read()
    head, _, body = t.partition('\r\n\r\n')
    return head, body.strip()

for label, folder, n, kind in [('LIVE session','saz_live/raw',6,'session'),
                               ('LIVE sdk_click','saz_live/raw',8,'click'),
                               ('MANUAL session','saz_new/raw',65,'session'),
                               ('MANUAL sdk_click','saz_new/raw',66,'click')]:
    head, body = load(folder, n)
    m = re.search(r'signature="([0-9A-F]+)"', head)
    blob = bytes.fromhex(m.group(1))
    hdr, enc, tag = blob[:16], blob[16:272], blob[272:]
    # 1. tag check (verify_tag takes full 304 B blob)
    ok_tag = A.verify_tag(blob)
    # 2. decrypt body with SEED, IV=header
    import hashlib, hmac as _hm
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(A.SEED), modes.CBC(hdr)).decryptor()
        rec = dec.update(enc) + dec.finalize()
        # strip pkcs7-ish tail: record ends with } \x00 + 0x10*16
        ok_rec = rec[255] == 0x10 and b'"e": "' in rec
        # 3. recompute commitment from sent fields
        fields = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
        from datetime import datetime, timezone
        def to_sec(s):
            mm = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z([+-]\d\d)(\d\d)', s)
            base = datetime.strptime(mm.group(1), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
            return int(base - int(mm.group(3))*3600 - int(mm.group(4))*60)
        sec = to_sec(fields['sent_at'])
        auth2 = A.mint_adj7(kind, fields, unix_sec=sec, include_block2=True,
                            campaign={"package_name":"in.hanafintech","app_version":"3.0.4","app_token":"smxi7gqwu39c","client_sdk":"android5.6.0","cert_sha1":"c1bfafcaffb84b805288b985fbe48e7f33d2c6df","adj_signing_id":"1300000","algorithm":"adj7","headers_id":"8","native_version":"3.62.0"})
        # can't match whole (random nonce) — compare header (deterministic per sec not per nonce? header is bionic(sec) deterministic)
        h2 = re.search(r'signature="([0-9A-F]+)"', auth2).group(1)
        print(label, 'tag_ok=', ok_tag, 'rec_ok=', ok_rec, 'header_match=', h2[:32]==m.group(1)[:32])
    except Exception as e:
        print(label, 'ERR', type(e).__name__, e)
