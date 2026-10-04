"""d4bridge2.py - extend the R/X bridge to every d4 word + #2.

For each row (canonical tile): R, X=T0^T1, Xhi, Xlo, W0, d2, a[0..7].
Test per d4 word a[k]: hi==R? lo==R? hi==(Xhi^R)? lo==(Xhi^R)? hi==Xlo?
lo==Xlo? hi==W0hi? lo==W0lo? etc. Report full table + exact matches.
Also #2 halves vs same set.
"""
import json, os, sys
HERE=os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M=0xFFFFFFFF
S=json.load(open(os.path.join(HERE,"all_signings.json"),encoding="utf-8"))
A=json.load(open(os.path.join(HERE,"app_signings.json"),encoding="utf-8"))[0]
def canon(x):
 raw=bytes.fromhex(x["d0"]); w=[int.from_bytes(raw[j:j+4],"big") for j in range(0,len(raw),4)]
 for t in (w[1:5],w[5:9]):
  K13=(t[3]^t[1])&M; R=(K13>>16)&0xFFFF
  if (((t[2]^t[0])&M)>>16)&0xFFFF==R: return w[0],t,R
 return w[0],w[1:5],None
ROWS=[]
for i,x in enumerate(S): ROWS.append((i,x["d0"],x["d2"],x["d4"]))
ROWS.append(("app",A["d0"],A["d2"],A["d4"]))
print("=== per-row base ===")
INFO=[]
for i,d0,d2,d4 in ROWS:
 W0,t,R=canon({"d0":d0}); X=(t[0]^t[1])&M; Xhi=(X>>16)&0xFFFF; Xlo=X&0xFFFF
 a=[int.from_bytes(bytes.fromhex(d4)[j:j+4],"big") for j in range(0,32,4)]
 d2v=int(d2,16)
 INFO.append((i,R,Xhi,Xlo,W0,t,a,d2v))
 print("[%-3s] R=%04x X=%08x W0=%08x d2=%08x"%(i,R,X,W0,d2v))
print()
print("=== d4[k] halves vs {R, Xhi, Xlo, W0hi, W0lo, d2hi, d2lo} ===")
names=["R","Xhi","Xlo","W0hi","W0lo","d2hi","d2lo"]
for k in range(8):
 print("-- a[%d] --"%k)
 for nm_idx,nm in enumerate(names):
  mh=ml=0; det=[]
  for i,R,Xhi,Xlo,W0,t,a,d2v in INFO:
   vals={"R":R,"Xhi":Xhi,"Xlo":Xlo,"W0hi":(W0>>16)&0xFFFF,"W0lo":W0&0xFFFF,"d2hi":(d2v>>16)&0xFFFF,"d2lo":d2v&0xFFFF}
   v=vals[nm]; hi=(a[k]>>16)&0xFFFF; lo=a[k]&0xFFFF
   if hi==v: mh+=1
   if lo==v: ml+=1
  if mh>=8 or ml>=8:
   print("   a[%d] hi==%s:%d/11 lo==%s:%d/11  <--"%(k,nm,mh,nm,ml))
 # also hi==(Xhi^R)? lo==(Xhi^R)? etc
 for expr,fn in [("Xhi^R",lambda R,Xhi,Xlo: (Xhi^R)&0xFFFF),("Xlo^R",lambda R,Xhi,Xlo:(Xlo^R)&0xFFFF),("Xhi^Xlo",lambda R,Xhi,Xlo:(Xhi^Xlo)&0xFFFF)]:
  mh=sum(1 for i,R,Xhi,Xlo,W0,t,a,d2v in INFO if ((a[k]>>16)&0xFFFF)==fn(R,Xhi,Xlo))
  ml=sum(1 for i,R,Xhi,Xlo,W0,t,a,d2v in INFO if (a[k]&0xFFFF)==fn(R,Xhi,Xlo))
  if mh>=8 or ml>=8: print("   a[%d] hi==%s:%d lo==%s:%d <--"%(k,expr,mh,expr,ml))
print()
print("=== #2 halves vs same set ===")
names2 = names + ["Xhi^R", "Xlo^R"]
for nm in names2:
    mh = ml = 0
    for i, R, Xhi, Xlo, W0, t, a, d2v in INFO:
        if nm == "Xhi^R":
            v = (Xhi ^ R) & 0xFFFF
        elif nm == "Xlo^R":
            v = (Xlo ^ R) & 0xFFFF
        elif nm in ("d2hi", "d2lo"):
            continue
        else:
            vals = {"R": R, "Xhi": Xhi, "Xlo": Xlo, "W0hi": (W0 >> 16) & 0xFFFF,
                    "W0lo": W0 & 0xFFFF}
            v = vals[nm]
        if ((d2v >> 16) & 0xFFFF) == v:
            mh += 1
        if (d2v & 0xFFFF) == v:
            ml += 1
    print("   d2 hi==%s:%d/11 lo==%s:%d/11" % (nm, mh, nm, ml))
print()
print("=== raw d4 table (for eyeball) ===")
for i,R,Xhi,Xlo,W0,t,a,d2v in INFO:
 print("[%-3s] R=%04x Xhi=%04x Xlo=%04x %s"% (i,R,Xhi,Xlo," ".join("%08x"%v for v in a)))
