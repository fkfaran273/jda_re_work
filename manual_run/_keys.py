"""_keys.py — with the static round keys in hand, is block32 computable?"""
import hashlib, hmac, re, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
sys.path.insert(0, '.')
import adj9_signature as SG

G = ["43fc368804c8ed1b17e5c8f603002f46","9e8f7ca2b2713e088c3f18324e1bc304",
"6d6ce7273cf15f697e41c2ca2814b8d9","610c29c68628429b5f420ffc440c99ad",
"a427a6a5cd83ac99e6973b069bd6d68a","eae0c558399dd296338a883f22d344c7",
"e4a5e9507c73109ccfb17ecf0132fd10","ca650736a6ad80f5c0725d9fb7f44c0d",
"de7183c8f757c6016db3ed9b39d445de","9a69cd0b699118abfcb610611e170939",
"e23bd37b4039402f78dff8e1145ee86a","1942b77e2586fa808c65bfb4c727e3d8",
"82758e3497199b4eba9336fafb988bc5","fdffaa1e8d2c05cb541cef2ac66e59a7",
"208b07e8e2c7c9f30d01aa5ca3cc74cc"]
keys = [bytes.fromhex(x) for x in G]
print('groups: %d, total %d bytes' % (len(keys), sum(len(k) for k in keys)))

b = open('../adj9/rev/creditsea/adj9_cap_declic.log','rb').read().decode('utf-8','replace')
blob_hex = re.findall(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]{384})", b)[0]
d = SG.decode_blob(bytes.fromhex(blob_hex))
rec = d['record']
block32 = rec[46:78]
print('block32: %s' % block32.hex())

# cross-check against the signer's own KB table
import adj9_signature
KB = getattr(adj9_signature, 'KB', None)
if KB:
    print('KB len %d ; group0 matches KB[:16]: %s' % (len(KB), bytes(KB[:16])==keys[0]))
    print('all 15 groups match KB in order:', all(bytes(KB[16*i:16*i+16])==keys[i] for i in range(15)))

# now: is block32 an AES of something under these keys?
F = {'S4': d['F_seed'].to_bytes(4,'big'),
     'd4': b''.join(w.to_bytes(4,'big') for w in SG._d4_words(d['F_seed'])),
     'd0': b''.join(w.to_bytes(4,'big') for w in SG._d0_words(SG._d4_words(d['F_seed']), head=(43,))),
     'claims': re.search(r'map_toString=\{([^}]*)\}', b).group(1).encode(),
     'cert': rec[25:45], 'magic': rec[0:3], 'head': rec[3:19],
     'block_pre': rec[0:46], 'rec46': rec[46:78]}
hits=[]
for kn,k in (('g0+g1', keys[0]+keys[1]), ('g14', keys[14]), ('all240', b''.join(keys))):
    for name,data in F.items():
        for mname, mk in (('ECB', lambda: modes.ECB()), ('CBC0', lambda: modes.CBC(b'\0'*16))):
            try:
                c=Cipher(algorithms.AES(k[:32].ljust(32,b'\0')), mk()).encryptor()
                out=c.update(data)+c.finalize()
            except Exception: continue
            if out[:32]==block32: hits.append('AES-%s key=%s data=%s'%(mname,kn,name))
        for suffix in (b'', b'\0'*16):
            pass
        if hashlib.sha256(data+k).digest()==block32: hits.append('sha256(data+%s)'%kn)
        if hmac.new(k,data,hashlib.sha256).digest()==block32: hits.append('hmac(%s,%s)'%(kn,name))
print()
print('HITS:', hits if hits else 'none')
