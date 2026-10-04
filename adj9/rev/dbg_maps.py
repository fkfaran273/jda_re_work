import subprocess
def su(cmd, timeout=30):
    return subprocess.run(["adb", "shell", "/debug_ramdisk/su", "-c", cmd],
                          capture_output=True, text=True, timeout=timeout).stdout
pid = su("pidof com.penti.app").strip().split()[0]
print("pid:", repr(pid))
maps = su("cat /proc/%s/maps" % pid)
print("maps bytes:", len(maps), "lines:", maps.count("\n"))
print(maps[:300])
