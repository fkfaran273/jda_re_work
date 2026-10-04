import re
# Walk capture6, reconstruct the inside-nSign event stream for ONE signing,
# and print the ordered sequence of jca events with key params.
data=open("cap/adj9_capture6.log","rb").read().decode("utf-8","ignore")
# events are ###ADJ9_BEGIN type=... ... ###ADJ9_END; but capture logs use older marker?
if "###ADJ9_BEGIN" not in data:
    print("markers:", data[:400]); raise SystemExit
evs=[]
for m in re.finditer(r"###ADJ9_BEGIN type=([\w_]+)[^\n]*\n(.*?)###ADJ9_END", data, re.S):
    evs.append((int(re.search(r"ts=(\d+)",m.group(0)).group(1)), m.group(1), m.group(2)))
print("events:",len(evs))
# nsign window = from 'nsign_in' to next 'nsign'
inside=False; seq=[]
for ts,t,body in evs:
    if t=="nsign_in": inside=True; seq=[]
    elif t=="nsign":
        inside=False
        seq.append(("RETURN", body.strip()[:200]))
        print("=== window ts=%d: %d events"%(ts,len(seq)))
        for t2,body2 in seq:
            one=" ".join(body2.split())[:170]
            print("  ",t2, one)
        seq=[] 
        break_flag=True
        break
    elif inside and t.startswith("jca_") or (inside and t in("oracle_",)):
        seq.append((t, body))
