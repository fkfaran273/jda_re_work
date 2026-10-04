# mint5_e1.py - E1 experiment: 2 piggy mints of the SAME map with the SAME
# stamps -> any differing dword = a random/counter input (#0/#2/#8 candidate).
# Kick the app with HOME cycles when no signing comes; fall back to pulling
# the persisted mint_outN.json from device storage.
import base64
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import frida

OUT = os.path.join(HERE, "mint_e1_result.json")
pkg = "com.penti.app"
ev = {"sigmap": None, "piggies": []}


def on_msg(m, data):
    if m.get("type") != "send":
        return
    p = m.get("payload", {})
    t = p.get("type")
    if t == "sigmap":
        ev["sigmap"] = {"act": p.get("activity"), "glob": p.get("globals")}
        print("[sigmap] act=%d glob=%d" % (len(p.get("activity") or []),
                                           len(p.get("globals") or [])), flush=True)
    elif t == "piggy":
        r = p.get("result", {})
        ev["piggies"].append(r)
        print("[piggy %d] ok=%s len=%s stamp=%s err=%s"
              % (len(ev["piggies"]), r.get("ok"), r.get("blobLen"),
                 r.get("stamp"), str(r.get("error"))[:120]), flush=True)
        try:
            json.dump({"piggies": ev["piggies"]},
                      open(os.path.join(HERE, "mint_e1_live.json"), "w"))
        except Exception:
            pass
    elif t == "log":
        print("[agent] %s" % str(p.get("note"))[:220], flush=True)
    elif t == "ready":
        print("[ready] errors=%s" % (p.get("errors"),), flush=True)
    elif t in ("block", "blocked", "killguard", "exception", "mint_result"):
        print("[ev:%s] %s" % (t, str(p)[:160]), flush=True)


def adb(*args):
    return subprocess.run(["adb"] + list(args), capture_output=True, text=True,
                          timeout=30).stdout


def kick():
    adb("shell", "input keyevent KEYCODE_HOME")
    time.sleep(2)
    adb("shell", "am start -n %s/.ui.main.MainActivity" % pkg)


def launch_pid():
    """ONE adb round-trip: launch, then poll pidof ON-DEVICE until the process
    exists (the shell loop is ~0.01 s/iteration, so we return the instant the
    pid appears — minimising the window before the anti-debug arms)."""
    cmd = ("am start -n %s/.ui.main.MainActivity >/dev/null 2>&1; "
           "i=0; while [ $i -lt 300 ]; do p=$(pidof %s); "
           "if [ -n \"$p\" ]; then echo PID:$p; break; fi; i=$((i+1)); done"
           % (pkg, pkg))
    out = adb("shell", cmd)
    for tok in (out or "").split():
        if tok.startswith("PID:"):
            return int(tok[4:].split()[0])
    return 0


def attach_tight(dev, pid, tries=60):
    """Attach IMMEDIATELY after launch: the anti-debug arms within ~1 s of
    process start (later attaches die with 'ptrace pokedata: I/O error'), so
    the first attempts must have no delay at all."""
    for attempt in range(tries):
        try:
            return dev.attach(pid)
        except Exception as e:
            print("[*] attach retry %d: %s" % (attempt + 1, str(e)[:70]),
                  flush=True)
            time.sleep(0.05 if attempt < 20 else 0.5)
    return None


dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")

# ATTACH-RACE: cold-start the app and attach inside the pre-guard window.
adb("shell", "am force-stop %s" % pkg)
time.sleep(1.0)
pid = launch_pid()
print("[*] launched pid", pid, flush=True)
sess = attach_tight(dev, pid) if pid else None
if sess is None:
    print("[F] attach failed (pid=%s)" % pid, flush=True)
    json.dump({"error": "attach failed", "pid": pid}, open(OUT, "w"), indent=1)
    sys.exit(1)
print("[*] attached pid", pid, flush=True)
scr = sess.create_script(open(os.path.join(HERE, "agent", "adj9agent.js"),
                              encoding="utf-8").read())
scr.on("message", on_msg)
scr.load()
print("[*] hooks live", flush=True)
time.sleep(2)

t0 = time.time()
kicked = 0
while len(ev["piggies"]) < 2 and time.time() - t0 < 240:
    time.sleep(5)
    if not ev["sigmap"] and time.time() - t0 > 25 and kicked < 1:
        kick(); kicked += 1
    elif ev["piggies"] and time.time() - t0 > 60 and kicked < 3:
        kick(); kicked += 1
        print("[*] kick %d" % kicked, flush=True)
    # persist piggies as they arrive ( survive runner death / adb drop )
    for _i, _p in enumerate(ev["piggies"]):
        try:
            json.dump({"piggies": ev["piggies"]},
                      open(os.path.join(HERE, "mint_e1_live.json"), "w"))
        except Exception:
            pass

# fallback: pull persisted files from the device
if len(ev["piggies"]) < 2:
    for i in (1, 2):
        r = adb("shell",
                "cat /storage/emulated/0/Android/data/%s/files/mint_out%d.json"
                % (pkg, i))
        if r.strip().startswith("{"):
            try:
                ev["piggies"].append(json.loads(r))
                print("[pull] mint_out%d.json" % i, flush=True)
            except Exception as e:
                print("[pull %d] parse err %s" % (i, e), flush=True)

res = {"piggies": [], "diff": None}
if len(ev["piggies"]) >= 2:
    a, b = ev["piggies"][0], ev["piggies"][1]
    ba = base64.b64decode(a["blobB64"] or "")
    bb = base64.b64decode(b["blobB64"] or "")
    same = ba == bb and len(ba) > 0
    diff_words = []
    if not same and len(ba) == len(bb) == 192:
        import struct
        wa = struct.unpack(">%dI" % (len(ba) // 4), ba)
        wb = struct.unpack(">%dI" % (len(bb) // 4), bb)
        diff_words = [i for i in range(len(wa)) if wa[i] != wb[i]]
    print("[diff] identical=%s  differing dwords: %s"
          % (same, diff_words), flush=True)
    res = {"piggies": [{"stamp": p.get("stamp"), "ok": p.get("ok"),
                        "blobLen": p.get("blobLen"),
                        "blob_b64": p.get("blobB64"),
                        "error": p.get("error")} for p in ev["piggies"]],
           "identical": same, "diff_dwords": diff_words,
           "sigmap": ev["sigmap"]}
json.dump(res, open(OUT, "w"), indent=1)
print("saved", OUT, flush=True)
try:
    sess.detach()
except Exception:
    pass
