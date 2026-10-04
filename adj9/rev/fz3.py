"""fz3.py - burst-window freeze capture, host-driven (64-bit safe)."""
import subprocess, sys, time, re
ADB = ["adb"]
def sh(cmd, timeout=60):
    return subprocess.run(ADB + ["shell", cmd], capture_output=True, text=True, timeout=timeout).stdout
def su(cmd, timeout=60):
    return subprocess.run(ADB + ["shell", "/debug_ramdisk/su -c '%s'" % cmd.replace("'", "'\"'\"'")],
                          capture_output=True, text=True, timeout=timeout).stdout
CYCLE = sys.argv[1] if len(sys.argv) > 1 else "3"
OUT = "/data/local/tmp/fz%s" % CYCLE
LOG = "/data/data/com.penti.app/files/adj9_capture.log"
print("[1] launch")
su("rm -rf %s; mkdir -p %s" % (OUT, OUT))
su("rm -f /data/data/com.penti.app/files/AdjustIoActivityState; am force-stop com.penti.app; am start -n com.penti.app/.ui.main.MainActivity")
print("[2] wait probe_start")
t0 = time.time()
base = su("grep -a -c probe_start %s" % LOG).strip()
while time.time() - t0 < 150:
    time.sleep(1)
    cur = su("grep -a -c probe_start %s" % LOG).strip()
    if cur != base and cur not in ("", "0"):
        break
print("probe started +%.0fs (cnt %s)" % (time.time() - t0, cur))
pid = su("pidof com.penti.app").strip().split()[0]
print("pid", pid)
maps = su("cat /proc/%s/maps" % pid)
open("fz%s_maps.txt" % CYCLE, "w").write(maps)
# stack tops
stacks = []
for line in maps.splitlines():
    if "stack" not in line or "rw-p" not in line:
        continue
    rng, rest = line.split()[0], line
    s, e = rng.split("-")
    s, e = int(s, 16), int(e, 16)
    top = e - 0x8000
    stacks.append((s, top))
print("stack regions:", len(stacks))
# scudo primary regions (for rotating slices)
scudo = []
for line in maps.splitlines():
    if "scudo:primary" in line and "rw-p" in line:
        rng = line.split()[0]
        s, e = rng.split("-")
        scudo.append((int(s, 16), int(e, 16)))
tot = sum(e - s for s, e in scudo)
print("scudo regions:", len(scudo), "total MB:", tot // 1048576)
SL = 262144
for rnd in range(1, 9):
    off = (rnd - 1) * SL
    cmds = ["kill -STOP %s" % pid]
    for i, (s, top) in enumerate(stacks):
        cmds.append("dd if=/proc/%s/mem of=%s/st%d_%d.bin bs=4096 skip=%d count=8 2>/dev/null"
                    % (pid, OUT, rnd, i, top // 4096))
    # heap slices: first 2 scudo regions, rotating offset
    for j, (s, e) in enumerate(scudo[:2]):
        if off < e - s:
            cmds.append("dd if=/proc/%s/mem of=%s/hp%d_%d.bin bs=262144 skip=%d iflag=skip_bytes count=1 count_bytes 2>/dev/null"
                        % (pid, OUT, rnd, j, s + off))
    cmds.append("kill -CONT %s" % pid)
    r = su("; ".join(cmds), timeout=90)
    alive = su("ps -A | grep -c com.penti.app").strip()
    print("round %d alive=%s" % (rnd, alive))
print("DONE cycle", CYCLE)
