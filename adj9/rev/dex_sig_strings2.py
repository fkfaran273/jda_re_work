import re
f="C:/Users/Apps/Downloads/com.penti.app/extracted/base/classes3.dex"
data=open(f,"rb").read()
pat=re.compile(rb"[\x20-\x7e]{4,}")
# The sig sdk strings are obfuscated base64: 'Y0D+Y0C+Y0R+Y0Q+' etc.
# Show ALL that match their alphabet pattern (upper, digits, +, =)
for m in pat.finditer(data):
    s=m.group().decode()
    if re.fullmatch(r"[A-Z0-9+/=]{8,}",s) and ("+" in s or "=" in s):
        print(repr(s))
