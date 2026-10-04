import re, glob, collections, struct
# Extract per-row blobs from rapid_batch rows across all logs
rows=[]
for lf in glob.glob("cap/*.log"):
    data=open(lf,"rb").read().decode("utf-8","ignore")
    for m in re.finditer(r"--- (\d+) t0=(\d+) t1=(\d+) ms=\d+ sec=(\d+) len=192\n([0-9a-f]{384})", data):
        idx,t0,t1,sec=int(m.group(1)),int(m.group(2)),int(m.group(3)),int(m.group(4))
        rows.append((lf,idx,sec,bytes.fromhex(m.group(5))))
print("rows:",len(rows))
# per-position hi stats over rapid rows only (should reproduce header law)
n=192
hi=[0]*n
for _,_,_,b in rows: 
    for i,x in enumerate(b):
        if x&0x80: hi[i]+=1
z=[i for i in range(n) if hi[i]==0]
print("hi==0 positions (rapid rows):",z, " rows:",len(rows))
# same-t0 sec pairs
from collections import defaultdict
bysec=defaultdict(list)
for r in rows: bysec[r[2]].append(r[3])
pairs=0; shareprefix=0
for sec,bs in bysec.items():
    if len(bs)>1:
        pairs+=len(bs)*(len(bs)-1)//2
        for i in range(len(bs)):
            for j in range(i+1,len(bs)):
                if bs[i][:16]==bs[j][:16]: shareprefix+=1
print("same-second pairs:",pairs,"shared 16B prefix:",shareprefix)
