"""Guard-proof memory forensics: locate libsigner.so descriptor-source struct in
com.penti.app heap and diff it across signings. No frida, no attach - only plain
root reads of /proc/PID/mem via block-skip dd (skip=BLOCKS, not bytes).
"""
import subprocess, os, sys, struct, json, re, base64, shutil

SERIAL = "ZD2228MY3X"
ROOT = r"C:\Users\Apps\Downloads\com.penti.app"
SD = os.path.join(ROOT, "adj9", "rev", "struct_diff")

# anchors (exact LE dword values from live capture)
A8PAT = struct.pack('<4I', 0xbfffffff, 0xfffffd1f, 0x00070000, 0)   # #8  at B+0x134
A9PAT = struct.pack('<I', 0xfad0f10d)                               # #9  at B+0x144 (first dword)
A9FULL = struct.pack('<5I', 0xfad0f10d, 0x60f93c17, 0x937b2f1e, 0xb6c09691, 0xae7d74bd)

def adb(args, timeout=300):
    p = subprocess.run(["adb", "-s", SERIAL] + args, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def su_sh(script, timeout=300):
    """Run a multi-line shell script on device as root (base64 to survive quoting)."""
    b64 = base64.b64encode(script.encode()).decode()
    rc, out, err = adb(["exec-out", "/debug_ramdisk/su -c 'echo %s | base64 -d | sh'" % b64], timeout)
    txt = out.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    return rc, txt

def parse_maps(text):
    out = []
    for line in text.splitlines():
        m = re.match(r'^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*?)\s*$', line)
        if not m:
            continue
        out.append({"lo": int(m.group(1), 16), "hi": int(m.group(2), 16),
                    "perms": m.group(3), "name": m.group(7)})
    return out

def select_ranges(ranges, mode):
    sel = []
    for r in ranges:
        if "rw" not in r["perms"]:
            continue
        n = r["name"]; size = r["hi"] - r["lo"]
        if size > 256 * 1024 * 1024:
            continue
        if mode == "main":
            if ("scudo" in n) or (n == "[anon:libc_malloc]"):
                sel.append(r)
        elif mode == "ext":   # all anonymous rw (named [anon:*] non-scudo + unnamed)
            if (n == "" or n.startswith("[anon:")):
                sel.append(r)
        elif mode == "all":   # everything rw
            sel.append(r)
    sel.sort(key=lambda r: r["lo"])
    for i, r in enumerate(sel):
        r["k"] = i; r["size"] = r["hi"] - r["lo"]
    return sel

def dump(pid, sel, tag):
    devdir = "/data/local/tmp/sd" + tag
    lines = [f"rm -rf {devdir}", f"mkdir -p {devdir}"]
    for r in sel:
        lines.append(f"dd if=/proc/{pid}/mem bs=4096 skip={r['lo']//4096} "
                     f"count={(r['hi']-r['lo'])//4096} of={devdir}/r{r['k']}.bin 2>/dev/null")
    # chunk so the base64 command line stays well under the device arg limit
    chunks, cur, cur_len = [lines[0:2]], [], 0  # first chunk = rm -rf + mkdir
    for line in lines[2:]:
        cur.append(line); cur_len += len(line) + 1
        if cur_len > 1300:
            chunks.append(cur); cur, cur_len = [], 0
    if cur:
        chunks.append(cur)
    chunks.append([f"ls -l {devdir}"])
    for i, ch in enumerate(chunks):
        rc, txt = su_sh("\n".join(ch) + "\n", timeout=600)
        if i == len(chunks) - 1:
            print(txt.strip())
        if rc != 0:
            print("  (chunk rc=%d)" % rc)

def pull(tag):
    devdir = "/data/local/tmp/sd" + tag
    dst = os.path.join(SD, tag)
    tmp = dst + "_pull"
    if os.path.exists(tmp):
        shutil.rmtree(tmp)
    adb(["pull", devdir, tmp], timeout=900)
    found = None
    for root, dirs, files in os.walk(tmp):
        if any(f.startswith("r") and f.endswith(".bin") for f in files):
            found = root; break
    if os.path.exists(dst):
        shutil.rmtree(dst)
    if found:
        shutil.move(found, dst)
        shutil.rmtree(tmp, ignore_errors=True)
    su_sh(f"rm -rf {devdir}\n")
    return dst

def find_all(buf, pat):
    hits, i = [], buf.find(pat)
    while i != -1:
        hits.append(i)
        i = buf.find(pat, i + 1)
    return hits

def extract(dst, sel, B, tag):
    for r in sel:
        if r["lo"] <= B and B + 0x200 <= r["hi"]:
            data = open(os.path.join(dst, f"r{r['k']}.bin"), "rb").read()
            fo = B - r["lo"]
            open(os.path.join(SD, f"{tag}_struct.bin"), "wb").write(data[fo:fo + 0x160])
            open(os.path.join(SD, f"{tag}_ctx.bin"), "wb").write(data[max(0, fo - 0x40):fo + 0x200])
            print(f"[{tag}] struct+ctx extracted from r{r['k']} "
                  f"(ctx {r['lo'] + max(0, fo-0x40):#x}..{r['lo'] + fo + 0x200:#x})")
            return True
    for r in sel:  # fallback: struct fits but context would cross range end
        if r["lo"] <= B and B + 0x160 <= r["hi"]:
            data = open(os.path.join(dst, f"r{r['k']}.bin"), "rb").read()
            fo = B - r["lo"]
            open(os.path.join(SD, f"{tag}_struct.bin"), "wb").write(data[fo:fo + 0x160])
            open(os.path.join(SD, f"{tag}_ctx.bin"), "wb").write(data[max(0, fo - 0x40):fo + 0x160])
            print(f"[{tag}] struct extracted (truncated ctx) from r{r['k']}")
            return True
    print(f"[{tag}] EXTRACT FAILED: B={B:#x} not covered by any dumped range")
    return False

def show_struct(tag):
    st = open(os.path.join(SD, f"{tag}_struct.bin"), "rb").read()
    print(f"[{tag}] struct dump ({len(st)}B):")
    for i in range(0, len(st), 16):
        row = st[i:i + 16]
        words = " ".join("%08x" % struct.unpack_from("<I", row, j)[0]
                         for j in range(0, len(row) - 3, 4))
        print("   %04x: %s" % (i, words))

def stage(tag, pid, mode="main", prefer_b=None):
    rc, maps = su_sh(f"cat /proc/{pid}/maps")
    open(os.path.join(SD, f"maps_{tag}.txt"), "w").write(maps)
    ranges = parse_maps(maps)
    if len(ranges) < 10:
        print("MAPS LOOK WRONG (head):", maps[:400]); sys.exit(2)
    sel = select_ranges(ranges, mode)
    total = sum(r["size"] for r in sel)
    print(f"[{tag}] mode={mode} pid={pid} ranges={len(sel)} total={total/1e6:.2f}MB")
    for r in sel:
        print(f"   r{r['k']:>2} {r['lo']:#012x}-{r['hi']:#012x} {r['size']:>10} {r['name']}")
    dump(pid, sel, tag)
    dst = pull(tag)
    info = {"tag": tag, "pid": pid, "mode": mode, "ranges": sel, "a8_hits": [], "cands": []}
    for r in sel:
        p = os.path.join(dst, f"r{r['k']}.bin")
        if not os.path.exists(p):
            print(f"   r{r['k']} MISSING"); r["ok"] = False; r["got"] = 0; continue
        data = open(p, "rb").read()
        r["got"] = len(data); r["ok"] = (len(data) == r["size"])
        if not r["ok"]:
            print(f"   r{r['k']} SIZE {len(data)} != {r['size']}")
        a8offs = set(find_all(data, A8PAT))
        for off in find_all(data, A8PAT):
            info["a8_hits"].append({"k": r["k"], "addr": r["lo"] + off,
                                    "a9": data[off+0x10:off+0x14] == A9PAT,
                                    "a9full": data[off+0x10:off+0x24] == A9FULL})
        for off in find_all(data, A9FULL):  # stray #9 without preceding #8
            if (off - 0x10) not in a8offs:
                info["a8_hits"].append({"k": r["k"], "addr": r["lo"] + off,
                                        "a9only": True, "a9full": True})
    if info["a8_hits"]:
        print(f"[{tag}] anchor hits: " + ", ".join(
            f"{h['addr']:#x}(r{h['k']},a9full={h.get('a9full')})" for h in info["a8_hits"]))
    else:
        print(f"[{tag}] NO anchor hits in mode={mode}")
    for h in info["a8_hits"]:
        B = h["addr"] - 0x134
        r = sel[h["k"]]
        data = open(os.path.join(dst, f"r{r['k']}.bin"), "rb").read()
        fo = B - r["lo"]
        if fo < 0 or fo + 0x160 > len(data):
            continue
        claims = struct.unpack_from("<I", data, fo + 8)[0]
        h["B"] = B; h["claims_len"] = claims
        h["score"] = (1 if h.get("a9full") else 0, 1 if 0 < claims < 0x100000 else 0)
        info["cands"].append(h)
    best = None
    if info["cands"]:
        top = max(c["score"] for c in info["cands"])
        pool = [c for c in info["cands"] if c["score"] == top]
        if prefer_b is not None and len(pool) > 1:
            pool.sort(key=lambda c: abs(c["B"] - prefer_b))
        best = pool[0]
    info["best"] = best
    if best:
        print(f"[{tag}] BEST: #8@{best['addr']:#x}  B={best['B']:#x}  "
              f"claims_len={best['claims_len']:#x}  a9full={best.get('a9full')}")
        extract(dst, sel, best["B"], tag)
        show_struct(tag)
    json.dump(info, open(os.path.join(SD, f"info_{tag}.json"), "w"), indent=1)
    return best

HUNT_HDR = ("PID={pid}\nOUT=/data/local/tmp/hunt{tag}\n"
            "rm -rf $OUT; mkdir -p $OUT\n"
            "PAT8=$(printf '\\377\\377\\377\\277\\037\\375\\377\\377')\n"
            "PAT9=$(printf '\\015\\361\\320\\372')\n"
            "chk(){{ m=$(dd if=/proc/$PID/mem bs=4096 skip=$1 count=$2 2>/dev/null | "
            "grep -aob -e \"$PAT8\" -e \"$PAT9\" | head -2); "
            "[ -n \"$m\" ] && {{ echo \"HIT $1 :: $m\"; "
            "dd if=/proc/$PID/mem bs=4096 skip=$1 count=$2 of=$OUT/b$1.bin 2>/dev/null; }}; }}\n")

def dump_one(pid, lo, hi, localpath):
    """Block-skip dd one range [lo,hi) from /proc/pid/mem, pull to localpath."""
    dev = "/data/local/tmp/grab.bin"
    script = (f"rm -f {dev}\n"
              f"dd if=/proc/{pid}/mem bs=4096 skip={lo//4096} count={(hi-lo)//4096} of={dev} 2>/dev/null\n"
              f"ls -l {dev}\n")
    rc, txt = su_sh(script, timeout=300)
    if "No such file" in txt:
        return None
    ptmp = localpath + ".pull"
    if os.path.exists(ptmp):
        os.remove(ptmp)
    adb(["pull", dev, ptmp], timeout=300)
    su_sh(f"rm -f {dev}\n")
    if os.path.exists(ptmp):
        if os.path.exists(localpath):
            os.remove(localpath)
        shutil.move(ptmp, localpath)
        return open(localpath, "rb").read()
    return None

def find_struct_in(data, lo, tag, k=None, src=""):
    """Search full anchors in one range image; return best candidate dict or None."""
    cands = []
    a8offs = find_all(data, A8PAT)
    for off in a8offs:
        addr = lo + off
        a9f = data[off+0x10:off+0x24] == A9FULL
        B = addr - 0x134
        if B < lo or B + 0x160 > lo + len(data):
            continue
        fo = B - lo
        claims = struct.unpack_from("<I", data, fo + 8)[0]
        cands.append({"addr": addr, "B": B, "k": k, "claims_len": claims,
                      "a9full": a9f, "src": src,
                      "score": (1 if a9f else 0, 1 if 0 < claims < 0x100000 else 0)})
    for off in find_all(data, A9FULL):
        if (off - 0x10) not in set(a8offs):
            print(f"   stray #9-only hit at {lo+off:#x} ({src})")
    if not cands:
        return None
    top = max(c["score"] for c in cands)
    pool = [c for c in cands if c["score"] == top]
    return pool[0]

def save_struct(data, lo, B, tag):
    fo = B - lo
    st = data[fo:fo + 0x160]
    ctx = data[max(0, fo - 0x40):fo + 0x200]
    open(os.path.join(SD, f"{tag}_struct.bin"), "wb").write(st)
    open(os.path.join(SD, f"{tag}_ctx.bin"), "wb").write(ctx)
    return st

def hunt(tag, pid):
    """On-device hunt: dd|grep every anon rw range for the anchor patterns.
    Scudo/libc_malloc ranges first, then all other anon rw. Saves hit range images."""
    rc, maps = su_sh(f"cat /proc/{pid}/maps")
    open(os.path.join(SD, f"maps_{tag}.txt"), "w").write(maps)
    ranges = parse_maps(maps)
    main_sel = select_ranges(ranges, "main")
    mainlos = {r["lo"] for r in main_sel}
    ext_only = [r for r in select_ranges(ranges, "ext") if r["lo"] not in mainlos]
    sel = main_sel + ext_only
    for i, r in enumerate(sel):
        r["k"] = i
    total = sum(r["size"] for r in sel)
    print(f"[hunt {tag}] pid={pid} ranges={len(sel)} total={total/1e6:.1f}MB "
          f"(scudo/libc {len(main_sel)}, ext-only {len(ext_only)})")
    out = {"tag": tag, "pid": pid, "ranges": sel, "hit_lines": [], "best": None}
    hdr = HUNT_HDR.format(pid=pid, tag=tag)
    lines = [f"chk {r['lo']//4096} {(r['hi']-r['lo'])//4096}" for r in sel]
    chunks, cur, ln = [], [], len(hdr)
    for L in lines:
        if ln + len(L) + 1 > 2200:
            chunks.append(hdr + "\n".join(cur) + "\n"); cur, ln = [], len(hdr)
        cur.append(L); ln += len(L) + 1
    if cur:
        chunks.append(hdr + "\n".join(cur) + "\n")
    chunks.append(f"PID={pid}\nls -l /data/local/tmp/hunt{tag}\n")
    for ch in chunks:
        rc, txt = su_sh(ch, timeout=900)
        for line in txt.splitlines():
            if line.startswith("HIT"):
                print("  " + line)
                out["hit_lines"].append(line)
    # pull hit range images
    outdir = f"/data/local/tmp/hunt{tag}"
    local = os.path.join(SD, f"hunt_{tag}")
    if os.path.exists(local):
        shutil.rmtree(local)
    os.makedirs(local, exist_ok=True)
    rc, o, e = adb(["pull", outdir, local + "_p"], timeout=600)
    su_sh(f"rm -rf {outdir}\n")
    src = None
    for root, dirs, files in os.walk(local + "_p"):
        if any(f.startswith("b") for f in files):
            src = root; break
    if src:
        for f in os.listdir(src):
            shutil.move(os.path.join(src, f), os.path.join(local, f))
    shutil.rmtree(local + "_p", ignore_errors=True)
    # verify hits with full patterns locally
    best = None
    for line in out["hit_lines"]:
        blk = int(line.split()[1])
        for r in sel:
            if r["lo"] // 4096 == blk:
                p = os.path.join(local, f"b{blk}.bin")
                if not os.path.exists(p):
                    break
                data = open(p, "rb").read()
                c = find_struct_in(data, r["lo"], tag, k=r["k"], src=f"b{blk}.bin")
                if c:
                    print(f"  FULL MATCH at {c['addr']:#x} B={c['B']:#x} "
                          f"claims_len={c['claims_len']:#x} a9full={c['a9full']} ({f})")
                    if best is None or c["score"] > best["score"]:
                        best = c
                break
    out["best"] = best
    if best:
        r = sel[best["k"]]
        data = open(os.path.join(local, f"b{r['lo']//4096}.bin"), "rb").read()
        st = save_struct(data, r["lo"], best["B"], tag)
        print(f"[hunt {tag}] struct saved ({len(st)}B) from range "
              f"{r['lo']:#x}-{r['hi']:#x} file b{r['lo']//4096}.bin")
        show_struct(tag)
    else:
        print(f"[hunt {tag}] raw hits: {len(out['hit_lines'])}, full-pattern matches: 0")
    json.dump(out, open(os.path.join(SD, f"info_{tag}.json"), "w"), indent=1)
    return best

def grab(tag, pid, B):
    """Fast re-read of one page window around a known struct base; verify anchors."""
    lo = ((B - 0x1000) // 4096) * 4096
    hi = ((B + 0x2000) // 4096) * 4096
    data = dump_one(pid, lo, hi, os.path.join(SD, f"grab_{tag}.bin"))
    if not data:
        print(f"[grab {tag}] read failed")
        return None
    fo = B - lo
    ok8 = data[fo + 0x134:fo + 0x144] == A8PAT
    ok9 = data[fo + 0x144:fo + 0x158] == A9FULL
    claims = struct.unpack_from("<I", data, fo + 8)[0]
    print(f"[grab {tag}] B={B:#x} pid={pid} #8ok={ok8} #9ok={ok9} claims_len={claims:#x}")
    if not (ok8 and ok9):
        return None
    st = save_struct(data, lo, B, tag)
    show_struct(tag)
    json.dump({"tag": tag, "pid": pid, "B": B, "claims_len": claims,
               "grab_lo": lo, "grab_hi": hi},
              open(os.path.join(SD, f"info_{tag}.json"), "w"), indent=1)
    return {"B": B, "claims_len": claims, "pid": pid}

def cmp(a_tag, b_tag, quiet=False):
    a = open(os.path.join(SD, f"{a_tag}_struct.bin"), "rb").read()
    b = open(os.path.join(SD, f"{b_tag}_struct.bin"), "rb").read()
    n = min(len(a), len(b))
    ch = []
    for off in range(0, n - 3, 4):
        va = struct.unpack_from("<I", a, off)[0]
        vb = struct.unpack_from("<I", b, off)[0]
        if va != vb:
            ch.append((off, va, vb))
    runs = []
    for off, va, vb in ch:
        if runs and off == runs[-1]["end"] + 4:
            runs[-1]["end"] = off; runs[-1]["items"].append((off, va, vb))
        else:
            runs.append({"start": off, "end": off, "items": [(off, va, vb)]})
    if not quiet:
        print(f"== {a_tag} -> {b_tag}: {len(ch)} changed dwords, {len(runs)} runs")
        for r in runs:
            print(f"  run {r['start']:#05x}..{r['end']:#05x}:")
            for off, va, vb in r["items"]:
                print(f"    {off:#05x}: {va:08x} -> {vb:08x}")
    return {"a": a_tag, "b": b_tag, "changed": ch, "runs": runs}

def main():
    cmd = sys.argv[1]
    if cmd == "stage":
        tag, pid = sys.argv[2], int(sys.argv[3])
        mode = "main"
        prefer = None
        for x in sys.argv[4:]:
            if x == "--ext": mode = "ext"
            elif x == "--all": mode = "all"
            else: prefer = int(x, 16)
        stage(tag, pid, mode, prefer)
    elif cmd == "cmp":
        cmp(sys.argv[2], sys.argv[3])
    elif cmd == "report":
        report()
    else:
        print("unknown cmd")

def region(runs, lo, hi):
    out = []
    for r in runs:
        for off, va, vb in r["items"]:
            if lo <= off <= hi:
                out.append((off, va, vb))
    return out

def report():
    i1 = json.load(open(os.path.join(SD, "info_t1.json")))
    i2 = json.load(open(os.path.join(SD, "info_t2.json")))
    i3 = json.load(open(os.path.join(SD, "info_t3.json")))
    d12 = cmp("t1", "t2", quiet=True)
    d23 = cmp("t2", "t3", quiet=True)
    d13 = cmp("t1", "t3", quiet=True)
    L = []
    L.append("# libsigner.so descriptor-source heap struct - diff across signings")
    L.append("")
    L.append("Device: motorola moto g42, serial ZD2228MY3X, Android 12, root via `/debug_ramdisk/su`, "
             "SELinux permissive. Target: com.penti.app.")
    L.append("")
    L.append("Method (no frida, no attach, process never killed): plain root block-skip `dd` of "
             "`/proc/PID/mem` scudo/libc_malloc ranges -> local search for the #8/#9 anchor words -> "
             "struct slice at B = A8 - 0x134 -> forced re-signing (wipe "
             "`/data/data/com.penti.app/files/AdjustIoActivityState`, HOME, relaunch MainActivity, "
             "PID unchanged) -> re-dump -> dword diff.")
    L.append("")
    L.append("## Anchor and PIDs")
    L.append("")
    L.append(f"- P1 = {i1['pid']}, stable across t1/t2/t3: "
             f"{'YES' if i1['pid'] == i2['pid'] == i3['pid'] else 'NO'}")
    b1, b2, b3 = i1.get("best"), i2.get("best"), i3.get("best")
    if b1:
        L.append(f"- t1: #8 anchor at A8 = {b1['addr']:#x} -> struct base B = {b1['B']:#x} "
                 f"(claims_len at B+0x08 = {b1['claims_len']:#x})")
    if b2:
        L.append(f"- t2: A8 = {b2['addr']:#x}, B = {b2['B']:#x} "
                 f"(claims_len = {b2['claims_len']:#x})"
                 + ("" if b1 is None else
                    (", same address as t1" if b2['B'] == b1['B'] else ", **MOVED** vs t1")))
    if b3:
        L.append(f"- t3: A8 = {b3['addr']:#x}, B = {b3['B']:#x} "
                 f"(claims_len = {b3['claims_len']:#x})"
                 + ("" if b2 is None else
                    (", same address as t2" if b3['B'] == b2['B'] else ", **MOVED** vs t2")))
    L.append(f"- t1 anchor hits total: {len(i1['a8_hits'])} "
             f"({', '.join(hex(h['addr']) for h in i1['a8_hits'])})")
    L.append("")
    L.append("## Range map K->(lo,hi) used for the dumps (t1 scan, block-skip dd)")
    L.append("")
    L.append("| K | lo | hi | size | name |")
    L.append("|---|----|----|------|------|")
    for r in i1["ranges"]:
        L.append(f"| r{r['k']} | {r['lo']:#x} | {r['hi']:#x} | {r['size']:#x} | {r['name']} |")
    L.append("")
    bad = [r["k"] for r in i1["ranges"] if not r.get("ok")]
    L.append(f"All dumped range sizes matched maps (missing/mismatched: "
             f"{'none' if not bad else bad}).")
    L.append("")
    def pair_block(d, title):
        L.append(f"## {title}")
        L.append("")
        L.append(f"{d['changed'].count and len(d['changed'])} changed dwords in "
                 f"{len(d['runs'])} runs (offsets are B-relative).")
        L.append("")
        if d["runs"]:
            L.append("| offset | t-old | t-new |")
            L.append("|--------|-------|-------|")
            for r in d["runs"]:
                L.append(f"| **{r['start']:#x}..{r['end']:#x}** | | |")
                for off, va, vb in r["items"]:
                    L.append(f"| {off:#x} | {va:08x} | {vb:08x} |")
            L.append("")
            cl = region(d["runs"], 0x08, 0x08)
            d2 = region(d["runs"], 0x64, 0x64)
            d4 = region(d["runs"], 0x74, 0x93)
            d0 = region(d["runs"], 0x94, 0x123)
            d8 = region(d["runs"], 0x134, 0x143)
            d9 = region(d["runs"], 0x144, 0x157)
            L.append("Targeted regions:")
            L.append("")
            L.append(f"- B+0x08 claims_length: " +
                     ("CHANGED " + "; ".join(f"{o:#x}: {a:08x}->{b:08x}" for o, a, b in cl)
                      if cl else "unchanged"))
            L.append(f"- B+0x64 descriptor #2 (1 dword): " +
                     ("CHANGED " + "; ".join(f"{o:#x}: {a:08x}->{b:08x}" for o, a, b in d2)
                      if d2 else "unchanged"))
            ch4 = [f"{o:#x}: {a:08x}->{b:08x}" for o, a, b in d4]
            L.append(f"- B+0x74..0x93 descriptor #4 (8 dwords): " +
                     (f"{len(d4)}/8 words changed - " + "; ".join(ch4) if ch4 else "unchanged"))
            ch0 = [f"{o:#x}: {a:08x}->{b:08x}" for o, a, b in d0]
            L.append(f"- B+0x94..0x123 descriptor #0 (36 dwords): " +
                     (f"{len(d0)}/36 words changed - " + "; ".join(ch0) if ch0 else "unchanged"))
            L.append(f"- B+0x134..0x143 (#8 anchor words): " +
                     ("CHANGED" if d8 else "unchanged"))
            L.append(f"- B+0x144..0x157 (#9 anchor words): " +
                     ("CHANGED" if d9 else "unchanged"))
            other = [x for x in d["changed"]
                     if not (0x08 <= x[0] <= 0x08 or 0x64 <= x[0] <= 0x64 or
                             0x74 <= x[0] <= 0x93 or 0x94 <= x[0] <= 0x123 or
                             0x134 <= x[0] <= 0x157)]
            if other:
                L.append("- Other offsets: " + "; ".join(
                    f"{o:#x}: {a:08x}->{b:08x}" for o, a, b in other))
            else:
                L.append("- Other offsets: none")
        else:
            L.append("(no changes)")
        L.append("")
    pair_block(d12, "t1 -> t2 (signing #1 -> signing #2)")
    pair_block(d23, "t2 -> t3 (signing #2 -> signing #3)")
    pair_block(d13, "t1 -> t3 (signing #1 -> signing #3, two signings apart)")
    L.append("## Files")
    L.append("")
    L.append("- `t1/`, `t2/`, `t3/`: full range dumps rK.bin (K = index in the map above, "
             "file covers [lo,hi) exactly)")
    L.append("- `t1_struct.bin` / `t2_struct.bin` / `t3_struct.bin`: B..B+0x160 slices")
    L.append("- `t1_ctx.bin` / `t2_ctx.bin` / `t3_ctx.bin`: B-0x40..B+0x200 context slices")
    L.append("- `maps_t1.txt` etc.: /proc/PID/maps snapshots; `info_t1.json` etc.: "
             "machine-readable scan results")
    L.append("- `forensic.py`: the tool used (maps parse -> block-skip dd -> pull -> "
             "anchor search -> slice -> diff)")
    open(os.path.join(SD, "STRUCT_DIFF.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("\n".join(L))

if __name__ == "__main__":
    main()
