import io
p = "appcap_reg_src.js"
t = io.open(p, encoding="utf-8").read()
old = "          REGION.push(['srcead', c.x8.toString(), c.x22.toString(), '0']);"
new = ("          var d0 = '?';\n"
       "          try { d0 = c.x8.readPointer().add(c.x22.toInt32() * 4).readU32().toString(16); } catch (e) { }\n"
       "          REGION.push(['srcead', c.x8.toString(), c.x22.toString(), d0]);")
assert old in t, "anchor missing"
t = t.replace(old, new)
io.open(p, "w", encoding="utf-8").write(t)
print("srcead now reads the data word")
