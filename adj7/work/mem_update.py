import io

p = (r"C:\Users\Apps\.zcode\cli\memories\projects"
     r"\com.penti.app-b22b4299c8659539\memory\adj7-niri-status.md")
src = io.open(p, encoding="utf-8").read()
anchor = "**LIVE FUNNELS ran Organic"
new = ("**H LAW FULLY CONFIRMED ON THE PIXEL PLAY INSTALL (2026-10-06 evening):** "
       "the payrupi.chls bodies were TRUNCATED by the extractor (real session = "
       "1280 B/46 fields, sdk_click 1576 B/50, attribution 692 B/23 incl. "
       "push_token on the wire; spans Content-Length-verified in "
       "work/diff_flow.py BODIES). With the REAL bodies: H = "
       "commit2(cert40, nonce, claims(map + activity_kind + client_sdk)) "
       "reproduces the device H byte-exact on session/sdk_click/attribution "
       "(event = 1 residual). push_token IS on the wire but EXCLUDED from the "
       "signed map (added post-signing). CERT WIRING BUG (user-spotted, "
       "fixed): the lean run_install.py rewrite dropped "
       "_ap.CERT_SHA1/CLIENT_SDK wiring so the H used the NUL prefix and "
       "claims lacked client_sdk -> invalid -> Organic; restored + verified "
       "(the reproduced record carries the cert). payrupi adid 556f8e2d now "
       "burned: our early wrong-H replay attempts (pre-fix) likely made the "
       "fraud suite null its VL-Alliance attribution - the replay now returns "
       "Organic for ANY signature incl. the genuine one (byte-exact genuine "
       "replay also Organic). The rule's clean verdict needs: a REAL fresh "
       "GAID (user: advertising-ID reset or team pool) -> funnel run "
       "(everything else proven) -> books non-organic -> replay its "
       "attribution -> stays non-organic. " + anchor)
src = src.replace(anchor, new, 1)
io.open(p, "w", encoding="utf-8").write(src)
print("memory updated")
