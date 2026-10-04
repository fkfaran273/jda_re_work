import subprocess
r = subprocess.run(
    ["adb", "shell", "/debug_ramdisk/su -c 'P=$(pidof com.penti.app | cut -d\" \" -f1); echo PID=$P; cat /proc/$P/task/*/comm | sort | uniq -c | sort -rn | head -30'"],
    capture_output=True, text=True, cwd="C:\\Users\\Apps\\Downloads\\com.penti.app")
print(r.stdout[-2000:])
print(r.stderr[-500:])
