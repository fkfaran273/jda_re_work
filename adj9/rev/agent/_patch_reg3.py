import io
p = "appcap_reg_src.js"
t = io.open(p, encoding="utf-8").read()

# persistent region arming: retry every 100 ms until libsigner maps (no fixed cap)
inject = (
    "    if (armTimer === null) {\n"
    "      armTimer = setInterval(function () {\n"
    "        try {\n"
    "          if (!regionArmed) {\n"
    "            var bb2 = libBase();\n"
    "            if (bb2) { var rr = hookRegion(bb2); if (rr === 'ok') { regionArmed = true; send({ type: 'log', note: 'region armed (timer)' }); } }\n"
    "            if (regionArmed) { clearInterval(armTimer); armTimer = null; }\n"
    "          }\n"
    "        } catch (e) { }\n"
    "      }, 100);\n"
    "    }\n"
)
anchor = "    return { ok: true, hk: hk, jb: jb, auto: true };"
if "armTimer" not in t:
    assert anchor in t, "anchor missing"
    t = t.replace(anchor, inject + anchor)
    t = t.replace("var autoTimer = null;", "var autoTimer = null;\nvar armTimer = null;")
io.open(p, "w", encoding="utf-8").write(t)
print("armTimer injected:", t.count("armTimer"))
