import re

src = open("hyp_run3.py", encoding="utf-8").read()
m = re.search(r"vals = \{(.*?)\}", src, re.DOTALL)
if m:
    txt = m.group(1)
    keys = re.findall(r'"(\w+)"\s*:', txt)
    print("vals has %d keys" % len(keys))
    for k in ("created_at", "installed_at", "updated_at", "app_token"):
        print("  %s: %s" % (k, k in keys))
else:
    print("no vals dict found")
