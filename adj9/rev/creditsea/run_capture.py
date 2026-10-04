"""run_capture.py — spawn creditsea under frida, capture the descriptor plane.

Flow (the signing only fires when the app SENDS a package, which happens on
the relaunch after a force-stop):
  1. spawn #1 under frida, resume, let the app come up (~8 s)
  2. adb force-stop com.creditsea.app   (kills pid #1 -> session #1 detaches)
  3. spawn #2 under frida WITH the script already loaded, resume
  4. capture ~90 s: the session package signing lands inside the window
"""
import frida, sys, json, time, os, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "frida_capture.jsonl")
PKG = "com.creditsea.app"
records = []

def on_message(msg, data):
    if msg.get("type") == "send":
        p = msg.get("payload", {})
        records.append(p)
        t = p.get("type", "?")
        if t in ("wrapper_call", "wrapper_out", "hits", "scan_done", "scan_err",
                 "header_hit", "status", "dump_err", "no_hit", "claims_err"):
            print(json.dumps(p)[:300], flush=True)
        with open(OUT, "a") as f:
            f.write(json.dumps(p) + "\n")
    elif msg.get("type") == "error":
        print("SCRIPT ERR:", msg.get("stack", "")[:500], flush=True)
        with open(OUT, "a") as f:
            f.write(json.dumps({"type": "script_error", "stack": msg.get("stack", "")}) + "\n")

def adb(*args):
    subprocess.run(["adb"] + list(args), capture_output=True, text=True, timeout=30)

def attach_spawned(dev, tag):
    pid = dev.spawn([PKG])
    session = dev.attach(pid)
    with open(os.path.join(HERE, "creditsea_descs.bundle.js"), encoding="utf-8") as f:
        src = f.read()
    script = session.create_script(src)
    script.on("message", on_message)
    script.load()
    dev.resume(pid)
    print(f"[{tag}] spawned pid {pid}, script loaded + resumed", flush=True)
    return pid, session, script

def main():
    if os.path.exists(OUT):
        os.remove(OUT)
    dev = frida.get_usb_device(timeout=10)
    print("device:", dev.name, flush=True)

    # stage 1: first cold start (does not sign; warms the app up)
    pid1, ses1, scr1 = attach_spawned(dev, "stage1")
    time.sleep(8)

    # stage 2: force-stop + relaunch UNDER frida (hooks installed before resume)
    adb("shell", "am", "force-stop", PKG)
    print("force-stopped; relaunching under frida in 2s...", flush=True)
    time.sleep(2)
    try:
        ses1.detach()
    except Exception:
        pass
    pid2, ses2, scr2 = attach_spawned(dev, "stage2")

    t0 = time.time()
    while time.time() - t0 < 90:
        time.sleep(2)
    dumps = [r for r in records if r.get("type") == "dump"]
    wraps = [r for r in records if r.get("type") == "wrapper_call"]
    outs = [r for r in records if r.get("type") == "wrapper_out"]
    print("total records:", len(records), "| wrapper_calls:", len(wraps),
          "| wrapper_outs:", len(outs), "| dumps:", len(dumps), flush=True)
    for r in outs:
        print("  out:", (r.get("hex") or "")[:96], "...", flush=True)
    for r in dumps:
        print("  dump:", r.get("tag"), r.get("addr"), len(r.get("hex", "")) // 2, "B", flush=True)
    try:
        ses2.detach()
    except Exception:
        pass
    print("detached; records in", OUT, flush=True)

if __name__ == "__main__":
    main()
