# decode_data_strings.py — parse the whole .data string table of libsigner.so.
# Law: entry = [k^p0][k^p1]...[k^pn][k] where pN = NUL (so last stored byte = key),
# entries packed back-to-back with 00 padding between them.
import struct
so="C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data=open(so,"rb").read()
e_shoff=struct.unpack_from("<Q",data,0x28)[0]
e_shentsize=struct.unpack_from("<H",data,0x3a)[0]
e_shnum=struct.unpack_from("<H",data,0x3c)[0]
e_shstrndx=struct.unpack_from("<H",data,0x3e)[0]
secs=[]
for i in range(e_shnum):
    off=e_shoff+i*e_shentsize
    name,typ,flags,addr,offset,size,link,info,align,entsize=struct.unpack_from("<IIQQQQIIQQ",data,off)
    secs.append((name,addr,offset,size))
shstr=secs[e_shstrndx]
def sname(n):
    e=data.index(b"\0",shstr[2]+n)
    return data[shstr[2]+n:e].decode()
sm={sname(s[0]):s for s in secs}
d=sm[".data"]
base,foff,size=d[1],d[2],d[3]
buf=data[foff:foff+size]

def printable(b):
    return all(32<=c<127 for c in b)

entries=[]
p=0
while p < len(buf):
    if buf[p]==0:
        p+=1; continue
    found=False
    # try increasing lengths; key = last byte of entry
    for L in range(2,220):
        if p+L>len(buf): break
        k=buf[p+L-1]
        if k==0: continue
        plain=bytes(c^k for c in buf[p:p+L-1])
        if printable(plain):
            # greedy check: is there a shorter valid entry? prefer shortest that
            # itself validates, BUT avoid false splits: also require that the next
            # byte after entry is 00 or start of another valid entry. Simplest:
            # accept the SHORTEST valid L only if plain doesn't end mid-word...
            # We'll accept shortest valid and let human review the output.
            entries.append((base+p,k,plain.decode("ascii")))
            p+=L
            found=True
            break
    if not found:
        p+=1

print("decoded entries:",len(entries))
out=open("data_strings_decoded.txt","w",encoding="utf-8")
for va,k,s in entries:
    line="0x%06x k=%02x  %s"%(va,k,s)
    print(line)
    out.write(line+"\n")
out.close()
