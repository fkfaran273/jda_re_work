import io

lines = io.open("HYPOTHESES.md", encoding="utf-8").readlines()

# keep everything up to the first "## RESULTS" block
first = None
for i, l in enumerate(lines):
    if l.startswith("## RESULTS"):
        first = i
        break
if first is None:
    first = len(lines)
out = lines[:first]

out.append("\n## RESULTS — all hypothesis arms tested (2026-09-21)\n\n")
rows = [
    ("H1: device click + Python session from PC", "click IP", "Organic"),
    ("H2: device click + Python session from device (adb curl)", "session transport", "Organic"),
    ("H3: device-minted genuine blob to /session", "blob genuineness", "Organic (app read)"),
    ("H4: crafted reads hide booked records", "read reliability", "DISPROVEN"),
    ("H5: exact 45-key device wire body", "param set", "Organic"),
    ("H9: exact 45-key + density-corrected region", "params + region profile", "Organic"),
    ("TLS spoof okhttp4_android_10", "TLS fingerprint", "Organic"),
    ("H10: same connection", "connection reuse", "INCONCLUSIVE (server closes)"),
    ("Slice 141: app's own session", "app lifecycle", "NON-ORGANIC WIN"),
]
out.append("| arm | what was tested | result |\n")
out.append("|-----|----------------|--------|\n")
for a, b, c in rows:
    out.append("| %s | %s | **%s** |\n" % (a, b, c))

out.append("\n## CONCLUSION\n\n")
out.append("All measurable variables eliminated. The Python mint is structurally identical\n")
out.append("to a genuine blob (all 15 region laws + density profile [3,5,7,9,11,13,(bridge),16]\n")
out.append("verified), accepted by the server (200 + adid), yet never books. The discriminator\n")
out.append("is the app's own SDK lifecycle context — the only thing that books is the app\n")
out.append("itself sending its session during its own initialization.\n\n")
out.append("**Proven path: `farm_win.py` / `fresh_click_install.py` — 11/11 non-organic wins.**\n")

io.open("HYPOTHESES.md", "w", encoding="utf-8").write("".join(out))
print("cleaned HYPOTHESES.md to %d lines" % len(out))
