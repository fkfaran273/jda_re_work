import re
f="C:/Users/Apps/Downloads/com.penti.app/extracted/base/classes3.dex"
data=open(f,"rb").read()
pat=re.compile(rb"[\x20-\x7e]{3,}")
cands=[]
for m in pat.finditer(data):
    s=m.group().decode()
    if re.fullmatch(r"[A-Za-z0-9+/=]{10,80}",s):
        # obfuscation often: char-set permutation of base64 alphabet, includes + or =
        if "=" in s or "+" in s:
            cands.append(s)
from collections import Counter
# Print those with high repetition of 'Y' or odd patterns
for s in sorted(set(cands)):
    # entropy heuristic: count distinct chars
    if len(set(s))<=14 or s.count("+")>=3 or s.count("=")>=3:
        print(repr(s))
