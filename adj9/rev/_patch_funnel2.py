import io
import re

t = io.open("run_funnel.py", encoding="utf-8").read()

old = """    gps = named.get("--gps") or PIN_GPS or str(uuid.uuid4())
    print("install gps:", gps, "(pinned)" if PIN_GPS else "(fresh)",
          flush=True)
    link = (named.get("--link") or (args[1] if len(args) > 1 else None)
            or LINK or F.DEFAULT_LINK)
    ref_pasted = named.get("--referrer") or REFERRER_PASTED
    link = link.replace("{click_id}", "clk-" + uuid.uuid4().hex[:12])
    link = link.replace("{sub3}", gps)
"""

new = """    link = (named.get("--link") or (args[1] if len(args) > 1 else None)
            or LINK or F.DEFAULT_LINK)
    ref_pasted = named.get("--referrer") or REFERRER_PASTED

    # GAID: CLI > PIN_GPS > the link's own idfa/gps_adid/click_id > fresh uuid
    gps = named.get("--gps") or PIN_GPS or ""
    if not gps and link:
        m = re.search(r"(?:idfa|gps_adid|click_id)=([A-Za-z0-9-]{8,})", link)
        if m:
            gps = m.group(1)
    if not gps:
        gps = str(uuid.uuid4())
    print("install gps:", gps, flush=True)

    # Expand BOTH placeholders to the GAID (matches the user's link pattern
    # where click_id and idfa both carry the GAID). If the link is already
    # expanded (real GAID inside), these replaces are no-ops.
    link = link.replace("{click_id}", gps).replace("{sub3}", gps)
"""
assert old in t, "main() anchor not found"
t = t.replace(old, new)
io.open("run_funnel.py", "w", encoding="utf-8").write(t)
print("main() gps/expand logic patched")
