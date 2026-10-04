import re

d = open(r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_srv2dev.bin",
         encoding="latin1").read()
print("bytes:", len(d))
# any tracker_token occurrences
for m in re.finditer(r'tracker_token.{0,8}([A-Za-z0-9]{8})', d):
    print("tracker_token ->", m.group(1))
print()
# any VKM / Organic markers
for m in re.finditer(r'(VKM[^"]{0,40}|Organic)', d):
    print("  ", m.group(0))
