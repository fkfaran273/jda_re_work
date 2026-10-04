import subprocess, re
subprocess.run(["adb", "shell", "/debug_ramdisk/su -c 'tail -c 3000000 /data/data/com.penti.app/files/adj9_capture.log > /data/local/tmp/olt3.log; chmod 644 /data/local/tmp/olt3.log'"],
               capture_output=True, cwd="C:\\Users\\Apps\\Downloads\\com.penti.app")
subprocess.run(["adb", "pull", "/data/local/tmp/olt3.log", "olt3.mlog"],
               capture_output=True, cwd="C:\\Users\\Apps\\Downloads\\com.penti.app\\adj9\\device")
d = open("..\\device\\olt3.mlog", encoding="utf-8", errors="replace").read()
parts = d.split("###ADJ9_BEGIN ")
n = 0
for p in parts[1:]:
    m = re.match(r"type=nsign_in .*?utf8len=\d+ ts=(\d+)\n", p)
    if not m:
        continue
    tx = p.split("text: ", 1)[1] if "text: " in p else ""
    h = re.search(r"arg3_hex=([0-9a-f]+)", tx)
    print(m.group(1), (h.group(1)[:16] + "..") if h else None)
    n += 1
print("total:", n)
