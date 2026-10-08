"""dry_diff.py -- dry-run field + claims differ (nothing is sent).

Builds session/click/attribution/event EXACTLY as run_winner.py does for a
live run, then compares them against the golden paid capture
(adj7/cap/payruki_again/raw 41/42/43/44) and prints, per request:

  1. missing keys (golden has, we don't)
  2. extra keys   (we have, golden doesn't)
  3. key ORDER    (position-by-position)
  4. value diffs, split into DYNAMIC (allowlisted: ids/times/uuid/reftag)
     vs STATIC (should be byte-equal -- any hit is a bug)
  5. claims diff (build_claims output: what the signature actually
     commits to -- a static claim diff here is what the server sees)

  python dry_diff.py            # full report
  python dry_diff.py -v         # + every value of every field
"""
import json
import os
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_winner as R          # the exact code a live run executes
import adj7_pure as sg

RAW = (r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap"
       r"\payruki_again\raw")

# dynamic fields that are allowed (expected) to differ
DYN = {
    "gps_adid", "android_uuid", "partner_params", "callback_params",
    "referrer", "created_at", "sent_at", "installed_at", "updated_at",
    "click_time", "click_time_server", "install_begin_time",
    "install_begin_time_server",
}
VERBOSE = "-v" in sys.argv


def load(idx):
    txt = open(os.path.join(RAW, "%02d_c.txt" % idx), encoding="utf-8").read()
    sep = "\r\n\r\n" if "\r\n\r\n" in txt else "\n\n"
    head, _, rest = txt.partition(sep)
    lines = head.replace("\r\n", "\n").split("\n")
    method, target, _ = lines[0].split(" ", 2)
    body = rest.replace("\r\n", "\n").strip()
    if method == "GET":
        return method, target, urllib.parse.parse_qsl(
            urllib.parse.urlsplit(target).query, keep_blank_values=True)
    return method, target, urllib.parse.parse_qsl(body, keep_blank_values=True)


def fixed_run_fields():
    """The exact field maps a live run would send (fixed ids/times so the
    diff is deterministic)."""
    gaid = "11111111-2222-4333-8444-555555555555"
    auuid = "99999999-8888-7777-6666-555555554444"
    ref = ("adjust_reftag=c8qfiHghBGWIw&utm_source=VL-Alliance"
           "&utm_campaign=HM2&utm_content=HM2_1722_")
    click_sec = 1791363751        # golden click second
    sec = click_sec + 212          # session at golden CTIT (+211.979)
    R.PARTNER_PARAMS = json.dumps(
        {"payrupik_c_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
        separators=(",", ":"))
    out = {
        "session": R.build_session_request(gaid, auuid, sec,
                                           click_sec=click_sec),
        "click": R.build_click_request(gaid, auuid, sec + 1, ref,
                                       click_sec=click_sec),
        "attribution": R.build_attribution_request(gaid, auuid, sec + 4),
        "event": R.build_event_request(gaid, auuid, sec + 5,
                                       click_sec=click_sec),
    }
    return gaid, auuid, click_sec, out


def diff(name, ours_pairs, gold_pairs):
    """Both are ordered (k, v) lists. Print a full report."""
    ok = True
    ok = report_set(name, ours_pairs, gold_pairs) and ok
    ok = report_order(name, ours_pairs, gold_pairs) and ok
    ok = report_values(name, ours_pairs, gold_pairs) and ok
    ok = report_claims(name, ours_pairs, gold_pairs) and ok
    return ok


def report_set(name, ours, gold):
    og = [k for k, _ in ours]
    gg = [k for k, _ in gold]
    missing = [k for k in gg if k not in og]
    extra = [k for k in og if k not in gg]
    print("[%s] keys: ours=%d golden=%d" % (name, len(og), len(gg)))
    if missing:
        print("   !! MISSING (golden has, we don't): %s" % missing)
    if extra:
        print("   !! EXTRA   (we send, golden doesn't): %s" % extra)
    if not missing and not extra:
        print("   key sets identical")
    return not missing and not extra


def report_order(name, ours, gold):
    og = [k for k, _ in ours]
    gg = [k for k, _ in gold]
    if og == gg:
        print("   order identical (position-by-position)")
        return True
    print("   !! ORDER differs:")
    for i, (a, b) in enumerate(zip(og, gg)):
        if a != b:
            print("      pos %2d: ours=%-28s golden=%s" % (i, a, b))
    for i in range(min(len(og), len(gg)), max(len(og), len(gg))):
        if i < len(gg):
            print("      pos %2d: ours=<absent>          golden=%s"
                  % (i, gg[i]))
        else:
            print("      pos %2d: ours=%-28s golden=<absent>"
                  % (i, og[i]))
    return False


def report_values(name, ours, gold):
    od, gd = dict(ours), dict(gold)
    bad = []
    dyn = []
    for k in gd:
        if k not in od:
            continue
        if od[k] == gd[k]:
            continue
        if k in DYN:
            dyn.append((k, od[k], gd[k]))
        else:
            bad.append((k, od[k], gd[k]))
    if bad:
        print("   !! STATIC value diffs (must be byte-equal):")
        for k, a, b in bad:
            print("      %-26s ours=%r golden=%r" % (k, a, b))
    else:
        print("   static values byte-equal (%d fields)" %
              (len(gd) - len(dyn)))
    if VERBOSE:
        for k, a, b in dyn:
            print("      dyn %-24s ours=%r golden=%r" % (k, a, b))
    elif dyn:
        print("   dynamic diffs: %s" % ", ".join(k for k, _, _ in dyn))
    return not bad


def claim_slots(kind, params, client_sdk=None):
    """The ordered (slot_name, value) list build_claims would emit --
    the same walk, but kept named so we can diff slot-by-slot."""
    m = dict(params)
    m.setdefault("activity_kind", kind)
    m.setdefault("client_sdk", client_sdk or "")
    split = sg.CLAIM_POOL.index("seq")
    profile = sg.CLAIM_POOL[:split]
    tail = sg.CLAIM_POOL[split:-2]
    block2 = sg.CLAIM_POOL[-2:]
    out = []
    for k in profile:
        if m.get(k) not in (None, ""):
            out.append((k, str(m[k])))
    out.append(("__pin__", sg.ADJ_SIGNING_ID))
    for k in tail:
        if m.get(k) not in (None, ""):
            out.append((k, str(m[k])))
    for k in block2:
        if m.get(k) not in (None, ""):
            out.append((k, str(m[k])))
    return out


def report_claims(name, ours, gold):
    """Slot-by-slot diff of what the signature commits to."""
    co = claim_slots(name, dict(ours),
                     client_sdk=R.CAMPAIGN["client_sdk"])
    cg = claim_slots(name, dict(gold),
                     client_sdk=R.CAMPAIGN["client_sdk"])
    so, sg_ = [k for k, _ in co], [k for k, _ in cg]
    if so != sg_:
        print("   !! CLAIM SLOT ORDER/SET differs:")
        miss = [k for k in sg_ if k not in so]
        extra = [k for k in so if k not in sg_]
        if miss:
            print("      missing slots: %s" % miss)
        if extra:
            print("      extra slots:   %s" % extra)
        if not miss and not extra:
            for i, (a, b) in enumerate(zip(so, sg_)):
                if a != b:
                    print("      pos %d: ours=%s golden=%s" % (i, a, b))
        return False
    bad, dyn = [], []
    do, dg = dict(co), dict(cg)
    for k, v in co:
        gv = dg[k]
        if v == gv:
            continue
        (dyn if k in DYN else bad).append((k, v, gv))
    if bad:
        print("   !! CLAIM values differ (server-verified, must match):")
        for k, v, gv in bad:
            print("      %-26s ours=%r golden=%r" % (k, v, gv))
    else:
        print("   claims match golden: %d slots, statics byte-equal, "
              "dynamic=%s" % (len(co), ", ".join(k for k, _, _ in dyn)
                              or "none"))
    return not bad


def report_wire(name, ours, gold, method, target, gold_raw_body):
    """Encoding: re-encode the GOLDEN field list with OUR encoder and
    compare byte-for-byte to what's on the wire.  A mismatch means the
    server parses different params than the capture did."""
    if method == "POST":
        enc = urllib.parse.urlencode(gold).encode()
    else:
        enc = urllib.parse.urlencode(gold, quote_via=urllib.parse.quote
                                     ).encode()
    ref = gold_raw_body.encode() if gold_raw_body else b""
    print("   encoder: ours=%dB golden=%dB byte-identical=%s"
          % (len(enc), len(ref), enc == ref if ref else "n/a"))
    if ref and enc != ref:
        for i in range(min(len(enc), len(ref))):
            if enc[i] != ref[i]:
                print("      first byte diff @%d: ours=%r golden=%r"
                      % (i, enc[i:i + 40], ref[i:i + 40]))
                break


def report_headers(name, gold_head_lines):
    """Header names/order: what the capture sent vs what call() sends."""
    golden = []
    for ln in gold_head_lines:
        if ": " in ln:
            golden.append(ln.split(": ", 1)[0])
    ours = ["Client-SDK", "Authorization"]
    if name != "attribution":
        ours.append("Content-Type")
    ours += ["User-Agent", "Host", "Connection", "Accept-Encoding"]
    if name != "attribution":
        ours.append("Content-Length")
    ok = ours == golden
    print("   headers ours  : %s" % ours)
    print("   headers golden: %s" % golden)
    if not ok:
        print("   !! header order/set differs")
    return ok


def raw_head_and_body(idx):
    txt = open(os.path.join(RAW, "%02d_c.txt" % idx),
               encoding="utf-8").read()
    sep = "\r\n\r\n" if "\r\n\r\n" in txt else "\n\n"
    head, _, rest = txt.partition(sep)
    lines = head.replace("\r\n", "\n").split("\n")
    return lines[1:], (rest.replace("\r\n", "\n").strip()
                       if lines[0].startswith("POST") else "")


def parse_ts(s):
    """'2026-10-07T14:29:01.000Z+0530' -> epoch seconds (UTC)."""
    import re as _re
    from datetime import datetime, timezone
    m = _re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z"
                  r"([+-]\d\d)(\d\d)", s)
    if not m:
        return None
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    off = int(m.group(3)) * 3600 + int(m.group(4)) * 60
    ms = int((m.group(2) or "0").ljust(3, "0")[:3])
    return base.replace(tzinfo=timezone.utc).timestamp() - off + ms / 1000.0


def report_timeline(name, ours, gold):
    """Offsets from click_time -- the 'click time and install times' law."""
    od, gd = dict(ours), dict(gold)
    keys = [k for k in ("click_time", "click_time_server",
                        "install_begin_time", "install_begin_time_server",
                        "installed_at", "updated_at", "created_at",
                        "sent_at") if k in gd or k in od]
    if not keys:
        return True
    o0 = parse_ts(od.get("click_time") or od.get("installed_at")
                  or od.get("created_at"))
    g0 = parse_ts(gd.get("click_time") or gd.get("installed_at")
                  or gd.get("created_at"))
    print("   -- timeline (offset from click_time, s) --")
    # law fields: exact equality required.  pacing fields (created/sent):
    # informationally compared -- the device picks those ms per run.
    LAW = {"click_time", "click_time_server", "install_begin_time",
           "install_begin_time_server", "installed_at", "updated_at"}
    bad = False
    for k in keys:
        ov = od.get(k)
        gv = gd.get(k)
        ot = parse_ts(ov) if ov else None
        gt = parse_ts(gv) if gv else None
        oa = ("%+.3f" % (ot - o0)) if (ot is not None and o0) else "-"
        ga = ("%+.3f" % (gt - g0)) if (gt is not None and g0) else "-"
        mark = ""
        if oa != "-" and ga != "-":
            try:
                delta = float(oa) - float(ga)
                if abs(delta) > 0.001:
                    tag = "LAW VIOLATION" if k in LAW else "pacing"
                    mark = "   <-- %s %+0.3f s" % (tag, delta)
                    if k in LAW:
                        bad = True
            except ValueError:
                pass
        elif bool(ov) != bool(gv):
            mark = "   <-- present only in %s" % (
                "golden" if gv else "ours")
            if k in LAW:
                bad = True
        print("      %-26s ours=%-8s golden=%-8s%s" % (k, oa, ga, mark))

    # story order: click <= installed_at <= created_at <= sent_at
    order_bad = False
    seq = [("click_time", od.get("click_time")),
           ("installed_at", od.get("installed_at")),
           ("created_at", od.get("created_at")),
           ("sent_at", od.get("sent_at"))]
    seq = [(k, parse_ts(v)) for k, v in seq if v]
    for (k1, t1), (k2, t2) in zip(seq, seq[1:]):
        if t1 is not None and t2 is not None and t1 > t2 + 0.001:
            print("      !! ORDER: %s (%s) is AFTER %s (%s)"
                  % (k1, od.get(k1), k2, od.get(k2)))
            order_bad = True
    if not order_bad:
        print("      story order ok: %s" % " <= ".join(k for k, _ in seq))
    return not bad and not order_bad


def raw_auth(idx):
    txt = open(os.path.join(RAW, "%02d_c.txt" % idx), encoding="utf-8").read()
    import re as _re
    m = _re.search(r"^Authorization: (.+)$", txt, _re.M)
    return m.group(1).strip() if m else ""


def parse_auth(a):
    """'Signature signature="HEX",adj_signing_id="..",...' -> (hex, attrs)."""
    import re as _re
    m = _re.match(r'Signature signature="([0-9A-Fa-f]+)"(.*)$', a)
    if not m:
        return "", a
    attrs = dict(_re.findall(r'(\w+)="([^"]*)"', m.group(2)))
    return m.group(1), attrs


def report_auth(name, ours_fields, gold_idx, sec):
    """The Authorization header: attributes, blob size, header second."""
    from datetime import datetime, timezone
    auth = R.sign(ours_fields, name if name != "click" else "click", sec)
    oh, oattrs = parse_auth(auth)
    gh, gattrs = parse_auth(raw_auth(gold_idx))
    print("      attrs ours  : %s" % oattrs)
    print("      attrs golden: %s" % gattrs)
    ok = True
    if oattrs != gattrs:
        print("      !! attribute diff")
        ok = False
    if len(oh) != len(gh):
        print("      !! blob hex len ours=%d golden=%d" % (len(oh),
                                                          len(gh)))
        ok = False
    else:
        print("      blob hex len ours=%d golden=%d (304 B body)"
              % (len(oh), len(gh)))
    # header second must equal the SENT second (golden row-41 law)
    blob = bytes.fromhex(oh)
    fields = dict(ours_fields)
    for label, k in (("created_at", "created_at"), ("sent_at", "sent_at")):
        if k in fields:
            t = parse_ts(fields[k])
            if t is not None:
                want = sg.make_header(int(t))
                hit = "  <-- header==%s second" % label if want == blob[:16] \
                    else ""
                print("      header vs %-10s: %s%s"
                      % (label, want == blob[:16], hit))
    if not sg.verify_tag(blob):
        print("      !! tag invalid")
        ok = False
    else:
        print("      tag ok, cert/nonce/record structure valid")
    return ok


def main():
    gaid, auuid, click_sec, ours = fixed_run_fields()
    gold = {"session": load(41), "click": load(42),
            "attribution": load(43), "event": load(44)}
    print("=" * 78)
    print("DRY-RUN DIFF  ours=run_winner.py builders  "
          "golden=payruki_again 41-44 (paid, booked 248wk8ym)")
    print("gaid=%s  click_sec=%d  INSTALL_AFTER=%d  MINT_SKEW=%d"
          % (gaid, click_sec, R.INSTALL_AFTER, R.MINT_SKEW))
    print("=" * 78)
    all_ok = True
    for idx, name in ((41, "session"), (42, "click"),
                      (43, "attribution"), (44, "event")):
        print()
        method, target, gpairs = gold[name]
        # dict insertion order IS the wire order (urlencode/parse_qsl)
        ok = diff(name, list(ours[name].items()), gpairs)
        head_lines, body = raw_head_and_body(idx)
        if method == "GET":
            body = urllib.parse.urlsplit(target).query
        print("   -- timeline --")
        report_timeline(name, ours[name], gpairs)
        print("   -- wire encoding --")
        report_wire(name, ours[name], gpairs, method, target, body)
        print("   -- http headers --")
        ok = report_headers(name, head_lines) and ok
        print("   -- authorization --")
        of = dict(ours[name])
        sec = int(parse_ts(of["created_at"]))
        ok = report_auth(name, of, idx, sec) and ok
        all_ok = all_ok and ok
    print()
    print("=" * 78)
    print("VERDICT: %s" % ("clean -- no static/claim delta"
                           if all_ok else "DIFFERENCES FOUND (above)"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
