import io
p = "appcap_reg_src.js"
t = io.open(p, encoding="utf-8").read()
old = "        if (!regionArmed) {\n"
new = ("        if (!hooked) { var h2 = hookPlanes(); if (h2 !== 'no-libsigner' && h2 !== 'already') send({ type: 'log', note: 'planes armed (timer)' }); }\n"
       "        if (!regionArmed) {\n")
assert old in t, "timer anchor missing"
t = t.replace(old, new, 1)
io.open(p, "w", encoding="utf-8").write(t)
print("planes now also arm via the timer")
