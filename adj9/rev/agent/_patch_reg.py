import io
p = "appcap_reg_src.js"
t = io.open(p, encoding="utf-8").read()
t = t.replace("if (!dumped && EMITS.length > 300) {",
              "if (!dumped && (EMITS.length > 300 || REGION.length >= RCAP)) {")
io.open(p, "w", encoding="utf-8").write(t)
print("autoflush-region count:", t.count("REGION.length >= RCAP"))
