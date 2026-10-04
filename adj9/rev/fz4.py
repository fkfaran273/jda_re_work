"""fz4.py - per-signing freeze capture, full heap rotation."""
import subprocess, sys, time, re
def sh(cmd, timeout=30):
    return subprocess.run(["adb", "shell", cmd], capture_output=True, text=True, timeout=timeout).stdout
def su(cmd, timeout=30):
    return subprocess.run(["adb", "shell", "/debug_ramdisk/su", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout).stdout
CYCLE = sys.argv[1] if len(sys.argv) > 1 else "4"
OUT = "/data/local/tmp/fz%s" % CYCLE
LOG = "/data/data/com.penti.app/files/adj9_capture.log"
print("[1] launch")
su("rm -rf %s; mkdir -p %s" % (OUT, OUT))
su("settings put system screen_off_timeout 1800000; svc power stayon true")
su("rm -f /data/data/com.penti.app/files/AdjustIoActivityState; am force-stop com.penti.app; am start -n com.penti.app/.ui.main.MainActivity")
su("input keyevent KEYCODE_WAKEUP")
base = su("stat -c %s " + LOG).strip()
print("base size:", base)
rounds = 0
t_end = time.time() + 420
while rounds < 20 and time.time() < t_end:
    time.sleep(0.1)
    cur = su("stat -c %s " + LOG).strip()
    if cur == base or not cur:
        continue
    base = cur
    rounds += 1
    print("[%d] growth detected, freezing" % rounds)
    pid = su("pidof com.penti.app").strip().split()
    if not pid:
        print("round %d: NO PID, relaunching" % (rounds + 1))
        su("am start -n com.penti.app/.ui.main.MainActivity")
        time.sleep(5)
        continue
    pid = pid[0]
    maps = su("cat /proc/%s/maps" % pid)
    if len(maps) < 10000:
        print("round %d: maps too short (%d), skipping" % (rounds + 1, len(maps)))
        time.sleep(2)
        continue
    open("fz%s_maps_r%d.txt" % (CYCLE, rounds), "w").write(maps)
    scudo = []
    for line in maps.splitlines():
        if "scudo:primary" in line and "rw-p" in line:
            rng = line.split()[0]
            s, e = rng.split("-")
            scudo.append((int(s, 16), int(e, 16)))
    stacks = []
    comms = su("for t in /proc/%s/task/*/; do echo $(basename $t):$(cat ${t}comm 2>/dev/null); done" % pid)
    want_tids = set()
    for ln in comms.splitlines():
        if ":" not in ln:
            continue
        tid, cn = ln.split(":", 1)
        if cn.startswith("pool") or cn.startswith("Adjust") or cn.startswith("adj9") or cn == "com.penti.app":
            want_tids.add(tid.strip())
    for line in maps.splitlines():
        if "rw-p" not in line:
            continue
        rng = line.split()[0]
        s, e = rng.split("-")
        tail = line.split()[-1] if len(line.split()) > 5 else ""
        m = re.match(r"\[anon:stack_and_tls:(\d+)\]", tail) or (["[stack]"] if tail == "[stack]" else None)
        if m:
            tid = m[0] if isinstance(m, list) else m.group(1)
            if tid == "[stack]" or tid in want_tids:
                stacks.append((int(s, 16), int(e, 16) - 0x8000))
    stacks = stacks[:12]
    cmds = ["kill -STOP %s" % pid]
    for i, (s, top) in enumerate(stacks):
        cmds.append("dd if=/proc/%s/mem of=%s/st%d_%d.bin bs=4096 skip=%d count=8 2>/dev/null"
                    % (pid, OUT, rounds, i, top // 4096))
    flat = sum(e - s for s, e in scudo)
    want = (rounds - 1) * 2097152 % max(flat, 1)
    acc = 0
    for (s, e) in scudo:
        if want < acc + (e - s) and want + 2097152 > acc:
            a = max(s, s + want - acc)
            b = min(e, a + 2097152)
            if b > a:
                cmds.append("dd if=/proc/%s/mem of=%s/hp%d.bin bs=1048576 skip=%d iflag=skip_bytes count=%d count_bytes 2>/dev/null"
                            % (pid, OUT, rounds, a, b - a))
                break
        acc += e - s
    cmds.append("kill -CONT %s" % pid)
    su("; ".join(cmds), timeout=100)
    alive = su("ps -A | grep -c com.penti.app").strip()
    print("round %d done alive=%s" % (rounds, alive))
print("DONE", rounds, "rounds")
