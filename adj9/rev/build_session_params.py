import re, json, base64

canon = open('clean_session_canon.txt', encoding='utf-8').read()
params = {}
for k, v in re.findall(r'([a-z_0-9]+)=([^,\n]*)', canon):
    params[k] = v
print("params from canonical:", len(params))
params.setdefault('adj_signing_id', '1500000')
params.setdefault('headers_id', '10')
params.setdefault('native_version', '5.0.0')
blob_b64 = open('transport_blob.txt').read().strip()
blob = base64.b64decode(blob_b64)
print("blob:", len(blob), "B")
auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
        'headers_id="10",native_version="5.0.0",adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % blob_b64)
json.dump({"params": params, "auth": auth, "blob_hex": blob.hex()},
          open("transport_session.json", "w"), indent=1)
print("saved transport_session.json")
print("params keys:", sorted(params.keys()))
