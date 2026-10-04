# Decode the JNI proto by looking at decoded .data strings near "putInt"/"put" etc
strs=open("rev/data_strings.txt","r",errors="ignore").read()
import re
for kw in ("putInt","putLong","put ","getInt","flip","array","ByteBuffer","allocate","order","wrap"):
    for line in strs.splitlines():
        if kw.lower()==line.strip().lower() or line.strip().startswith(kw):
            print(repr(line))
