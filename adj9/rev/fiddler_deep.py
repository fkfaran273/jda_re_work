# fiddler_deep.py — deep analysis of the Fiddler-captured signature (OnePlus DN2101, API 30)
import base64, struct, datetime, hashlib
SIG="QMgRTT9mxtofD3VyfhxE5s1jYqxb3XRxKZo988SMQaOuWQQfgYUsN1JK0QqRk7L5B6Te1pq+ltdKSmj8uG+6gaXboOKo5q+Lrm4pvjdw8w047bGpH2O4TfKLmKUgXv75iwrY3kxNTB7o93vEw9wC7YPpuD5ffEjIdbDsS5nonUQ4QQRXjhyXRVAEs8wlwwNaSqiKVLC/lRiEm5lfR88r2wMRsLKVZ5st267TQfQCKMY0unnK7uUl9r2QvMeNBNBQ"
b=base64.b64decode(SIG)
print("b64 len:",len(SIG)," raw bytes:",len(b))
print("first 16 (header):",b[:16].hex())
w=struct.unpack(">4I",b[:16])
print("as BE int32: %08x %08x %08x %08x -> %s"%(w[0],w[1],w[2],w[3],w))
print("MSB law (bytes 0,4,8,12 < 0x80):", [hex(b[i]) for i in (0,4,8,12)], "PASS" if all(b[i]<0x80 for i in (0,4,8,12)) else "FAIL -> words CAN exceed 31 bits on this device")
print("LE int32:",[hex(x) for x in struct.unpack("<4I",b[:16])])
# body entropy glance
print("body[16:] len:",len(b)-16)
# adj_verification check
AV="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
raw=base64.b64decode(AV)
key=b"Quoh8uafohgh7CahM2h"
plain=bytes(c^key[i%19] for i,c in enumerate(raw))
print("adj_verification decodes to:",plain.decode())
# timestamps -> epoch
for lbl,ts in [("created_at","2026-09-08T14:05:22.928+05:30"),("sent_at","2026-09-08T14:05:22.942+05:30"),
               ("installed_at","2026-09-08T14:00:02.774+05:30")]:
    dt=datetime.datetime.fromisoformat(ts)
    ep=dt.timestamp()
    print("%s -> epoch %d (.%03d)"%(lbl,int(ep),int(round((ep-int(ep))*1000))))
# compare with our moto blob header stats
print("\n=== our moto corpus first-16 stats for contrast ===")
import json,glob,re
def parse_events(path):
    lines=open(path,encoding="utf-8",errors="replace").read().splitlines()
    ev=[];cur=None
    for ln in lines:
        m=re.match(r"###ADJ9_BEGIN type=(\S+) utf8len=(\d+) ts=(\d+)",ln)
        if m: cur={"type":m.group(1),"ts":int(m.group(3)),"body":[]};ev.append(cur);continue
        if cur is not None:
            if ln.startswith("###ADJ9_END"):cur=None;continue
            cur["body"].append(ln)
    return ev
def field(e,name):
    j="\n".join(e["body"])
    m=re.search(r"(?:^|\s)"+name+r"=([^\s]+)",j,re.M)
    return m.group(1) if m else None
seen=set();n_pass=0;n=0
for path in glob.glob("C:/Users/Apps/Downloads/com.penti.app/adj9/cap/*.log"):
    for e in parse_events(path):
        if e["type"]=="nsign":
            h=field(e,"hex")
            if h and h not in seen:
                seen.add(h);n+=1
                bb=bytes.fromhex(h)
                if all(bb[i]<0x80 for i in (0,4,8,12)): n_pass+=1
print("moto blobs: %d/%d pass MSB law"%(n_pass,n))
