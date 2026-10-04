import re
f="C:/Users/Apps/Downloads/com.penti.app/extracted/base/classes3.dex"
data=open(f,"rb").read()
pat=re.compile(rb"[\x20-\x7e]{4,}")
keep=[]
for m in pat.finditer(data):
    s=m.group().decode()
    # strings used by the sig sdk: base64 alphabet, proto names, "ni:", version markers
    if re.fullmatch(r"[A-Za-z0-9+/=]+",s) and 16<=len(s)<=64: keep.append(("b64?",s))
    elif s.startswith("com.adjust.sdk.sig"): keep.append(("pkg",s))
    elif any(k in s.lower() for k in ("sign","verif","nonce","handshake","openssl","bks","keystore")) and len(s)<80: keep.append(("kw",s))
seen=set()
for t,s in keep:
    if s in seen: continue
    seen.add(s)
    print(t,repr(s))
