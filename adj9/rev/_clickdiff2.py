import json
rows = json.load(open("device/win_capture_rows.json"))
if isinstance(rows, dict): rows = rows.get("rows", rows)
real = None
for r in (rows if isinstance(rows, list) else []):
    if r.get("d10_hex") and len(r["d10_hex"])//2 in (386,387,388,390,391,392):
        real = bytes.fromhex(r["d10_hex"]).decode("latin1"); break
    if r.get("d10_hex") and r.get("head","2b 07")=="2b 22":  # H4 = click
        pass
# fallback: find the 387B one
if real is None:
    for r in rows:
        if r.get("d10_hex"):
            b = bytes.fromhex(r["d10_hex"])
            if len(b)==387:
                real = b.decode("latin1"); break
print("REAL click d10 len:", len(real) if real else None)
print("REAL d10:", real)
