"""parse_oracle.py -- reconstruct Signer.sign() calls from the ADJ7ORACLE
lines of the LSPosed modules log into adj7/work/hanaf_map.json.

Line shape:
[ ts   uid: pid: tid I/LSPosed-Bridge  ] ADJ7ORACLE: <msg>

msg shapes (from Hook.java):
  SIGN#<n> BEGIN <method> thread=<t>
  SIGN#<n> ARG<i> size=<m>                 (before-dump header)
  SIGN#<n> ARG<i> entries=<e> [c/t] <k=v | k=v ...>
  SIGN#<n> ARG<i>_AFTER size=<m>
  SIGN#<n> ARG<i>_AFTER entries=<e> [c/t] ...
  SIGN#<n> RET len=<L>
  SIGN#<n> RET blob_hex [c/t] <hex>
  SIGN#<n> END
  NSIGN <meth> arglens=... out_len=<L>
  NSIGN <meth> blob_hex [c/t] <hex>
"""
import json
import re
import sys

SRC = "adj7/work/lsposed_modules.log"
DST = "adj7/work/hanaf_map.json"

line_re = re.compile(r"\] ADJ7ORACLE: (.*)$")
calls = {}          # n -> dict
nsigns = []         # list of dicts
cur_nsign = None

order = []          # sign call numbers in appearance order

for raw in open(SRC, encoding="utf-8", errors="replace"):
    m = line_re.search(raw)
    if not m:
        continue
    msg = m.group(1).rstrip("\n")

    mm = re.match(r"SIGN#(\d+) BEGIN (.*)", msg)
    if mm:
        n = int(mm.group(1))
        calls.setdefault(n, {"n": n, "method": mm.group(2),
                             "args_before": {}, "args_after": {},
                             "ret_len": None, "ret_hex": ""})
        if n not in order:
            order.append(n)
        continue
    mm = re.match(r"SIGN#(\d+) ARG(\d+)(_AFTER)? size=(-?\d+)", msg)
    if mm:
        n, ai, aft, size = (int(mm.group(1)), int(mm.group(2)),
                            bool(mm.group(3)), int(mm.group(4)))
        d = calls.setdefault(n, {"n": n, "method": "", "args_before": {},
                                 "args_after": {}, "ret_len": None, "ret_hex": ""})
        tgt = d["args_after"] if aft else d["args_before"]
        tgt[ai] = {"size": size, "entries": [], "text": ""}
        continue
    mm = re.match(r"SIGN#(\d+) ARG(\d+)(_AFTER)? entries=(\d+) \[(\d+)/(\d+)\] (.*)$",
                  msg)
    if mm:
        n, ai, aft = (int(mm.group(1)), int(mm.group(2)), bool(mm.group(3)))
        d = calls.setdefault(n, {"n": n, "method": "", "args_before": {},
                                 "args_after": {}, "ret_len": None, "ret_hex": ""})
        tgt = d["args_after"] if aft else d["args_before"]
        if ai not in tgt:
            tgt[ai] = {"size": -1, "entries": [], "text": ""}
        # each chunk begins a NEW entry (dumpMap flushes at entry boundaries),
        # so restore the " | " separator the flush swallowed
        if tgt[ai]["text"]:
            tgt[ai]["text"] += " | "
        tgt[ai]["text"] += mm.group(7)
        continue
    mm = re.match(r"SIGN#(\d+) RET len=(\d+)", msg)
    if mm:
        calls.setdefault(int(mm.group(1)), {"n": int(mm.group(1)), "method": "",
                                            "args_before": {}, "args_after": {},
                                            "ret_len": None, "ret_hex": ""}
                         )["ret_len"] = int(mm.group(2))
        continue
    mm = re.match(r"SIGN#(\d+) RET blob_hex \[(\d+)/(\d+)\] (.*)$", msg)
    if mm:
        calls[int(mm.group(1))]["ret_hex"] += mm.group(4)
        continue
    if re.match(r"SIGN#\d+ END", msg):
        continue
    mm = re.match(r"NSIGN (\S+) arglens=(.*) out_len=(-?\d+)$", msg)
    if mm:
        cur_nsign = {"method": mm.group(1), "arglens": mm.group(2),
                     "out_len": int(mm.group(3)), "blob_hex": ""}
        nsigns.append(cur_nsign)
        continue
    mm = re.match(r"NSIGN (\S+) blob_hex \[(\d+)/(\d+)\] (.*)$", msg)
    if mm:
        # a fresh arglens line always precedes a blob for the same method --
        # if this method's last record already has hex, start a new one
        meth = mm.group(1)
        if cur_nsign is None or cur_nsign["method"] != meth \
                or cur_nsign["blob_hex"]:
            cur_nsign = {"method": meth, "arglens": "",
                         "out_len": -1, "blob_hex": ""}
            nsigns.append(cur_nsign)
        cur_nsign["blob_hex"] += mm.group(4)
        continue

# split "k=v | k=v" chunk text into ordered entries
def split_entries(text):
    out = []
    # values may contain " | "?  The SDK values (json, urls) don't contain the
    # " | " separator (we joined with " | " and values with '=' inside); split
    # on " | " only when the next token looks like key=value up to next " | ".
    parts = text.split(" | ")
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            out.append((k, v))
        else:
            if out:
                k, v = out[-1]
                out[-1] = (k, v + " | " + p)
            else:
                out.append(("<unparsed>", p))
    return out

result = []
for n in order:
    d = calls[n]
    entry = {"n": n, "method": d["method"]}
    # before maps
    for ai in sorted(d["args_before"]):
        a = d["args_before"][ai]
        ents = split_entries(a["text"])
        a["entries"] = ents
        entry["arg%d" % ai] = {k: v for k, v in ents}
        entry["arg%d_order" % ai] = [k for k, _ in ents]
    # after maps
    for ai in sorted(d["args_after"]):
        a = d["args_after"][ai]
        ents = split_entries(a["text"])
        a["entries"] = ents
        entry["arg%d_after" % ai] = {k: v for k, v in ents}
        entry["arg%d_after_order" % ai] = [k for k, _ in ents]
    entry["ret_len"] = d["ret_len"]
    entry["ret_hex"] = d["ret_hex"]
    # kind/endpoint hint
    kind = None
    for src_key in ("arg2", "arg2_after", "arg1", "arg1_after"):
        if src_key in entry and isinstance(entry[src_key], dict):
            if "activity_kind" in entry[src_key]:
                kind = entry[src_key]["activity_kind"]
                break
    entry["kind_hint"] = kind
    for src_key in ("arg1", "arg1_after"):
        if src_key in entry and isinstance(entry[src_key], dict) \
                and "event_token" in entry[src_key]:
            entry["event_token"] = entry[src_key]["event_token"]
    result.append(entry)

out = {"sign_calls": result, "nsign_calls": nsigns}

# ---- deliverable shape: one entry per sign() call -------------------------
captures = []
for e in result:
    si = e["n"] - 1
    ns = nsigns[2 * si] if 2 * si < len(nsigns) else None
    merged = {}
    order = []
    for k in ("arg1", "arg2"):
        if k in e:
            for kk, vv in e[k + "_order" ] and zip(e[k + "_order"],
                                                  [e[k][x] for x in e[k + "_order"]]) or []:
                if kk not in merged:
                    merged[kk] = vv
                    order.append(kk)
    nmap, norder = {}, []
    if ns is not None:
        i = ns["arglens"].find("{")
        j = ns["arglens"].rfind("}")
        if i >= 0 and j > i:
            pairs = []
            for f in ns["arglens"][i + 1:j].split(", "):
                if "=" in f:
                    kk, vv = f.split("=", 1)
                    pairs.append((kk, vv))
                elif pairs:
                    pk, pv = pairs[-1]
                    pairs[-1] = (pk, pv + ", " + f)
            nmap = dict(pairs)
            norder = [k for k, _ in pairs]
    captures.append({
        "kind_or_endpoint_hint": e.get("kind_hint"),
        "map": merged,
        "order": order,
        "blob_hex": ns["blob_hex"] if ns else e["ret_hex"],
        "sign_n": e["n"],
        "method": e["method"],
        "params_map": e.get("arg1", {}),
        "params_order": e.get("arg1_order", []),
        "globals_map": e.get("arg2", {}),
        "globals_order": e.get("arg2_order", []),
        "out_map": e.get("arg3_after", {}),
        "nsign_map": nmap,
        "nsign_order": norder,
        "nsign_blob_hex": ns["blob_hex"] if ns else None,
        "z22222_blob_hex": nsigns[2 * si + 1]["blob_hex"]
                           if 2 * si + 1 < len(nsigns) else None,
    })
out["captures"] = captures

with open(DST, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=1)

print("sign calls:", len(result), "nsign calls:", len(nsigns))
for e in result:
    sizes = []
    for k in sorted(e):
        if re.match(r"arg\d+(_after)?$", k) and isinstance(e[k], dict):
            sizes.append(k + "=" + str(len(e[k])))
    print(" SIGN#%d %s kind=%s %s ret_len=%s ret_hex=%d"
          % (e["n"], e["method"][:80], e["kind_hint"], " ".join(sizes),
             e["ret_len"], len(e["ret_hex"]) // 2))
for i, ns in enumerate(nsigns):
    print(" NSIGN#%d %s out_len=%s blob=%dB arglens=%dchars"
          % (i, ns["method"], ns["out_len"], len(ns["blob_hex"]) // 2,
             len(ns["arglens"])))
