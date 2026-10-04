import glob, struct, sys
# crude dex string search: find 'shorty' style or class names containing sig
files=glob.glob("C:/Users/Apps/Downloads/com.penti.app/extracted/**/*.dex", recursive=True)
print(len(files),"dex files")
import re
pat=re.compile(rb"[\x20-\x7e]{6,}")
for f in files:
    data=open(f,"rb").read()
    hits=set()
    for m in pat.finditer(data):
        s=m.group().decode()
        if ("sig" in s.lower() and ("adjust" in s.lower() or "native" in s.lower())) or "NativeLibHelper" in s or s.startswith("Lcom/adjust/sdk/sig"):
            hits.add(s)
    if hits:
        print(f.split("extracted")[-1], len(hits))
        for h in sorted(hits)[:25]: print("   ",h)
