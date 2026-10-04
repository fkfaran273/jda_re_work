import subprocess, re, glob, os
def adb(*a, timeout=60):
    return subprocess.run(["adb"] + list(a), capture_output=True, text=True, timeout=timeout).stdout
def su(cmd, timeout=60):
    return subprocess.run(["adb", "shell", "/debug_ramdisk/su", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout).stdout
print(su("ls /data/local/tmp/fz8/ | wc -l; du -sh /data/local/tmp/fz8"))
print(adb("pull", "/data/local/tmp/fz8", "fz8")[-300:])
# recent H values
r = su("grep -a -o -E arg3_hex=[0-9a-f]+ /data/data/com.penti.app/files/adj9_capture.log | tail -6")
Hs = re.findall(r"arg3_hex=([0-9a-f]{64})", r)
print(len(Hs), "recent H")
files = glob.glob("..\\device\\fz8\\*.bin")
print(len(files), "dump files")
hits = 0
for f in files:
    try:
        d = open(f, "rb").read()
    except Exception:
        continue
    for i, h in enumerate(Hs):
        if bytes.fromhex(h) in d:
            print("HIT H%d in %s" % (i, os.path.basename(f)))
            hits += 1
print("total:", hits)
