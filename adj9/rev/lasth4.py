import subprocess, re
r = subprocess.run(["adb", "shell", "/debug_ramdisk/su -c 'grep -a type=nsign_in /data/data/com.penti.app/files/adj9_capture.log | tail -8'"],
                   capture_output=True, text=True, cwd="C:\\Users\\Apps\\Downloads\\com.penti.app")
print(r.stdout[-1500:])
# full H list via python on pulled tail already present? use olt3 (3MB, 1 entry) - need bigger: grep count
r2 = subprocess.run(["adb", "shell", "/debug_ramdisk/su -c 'grep -a -c type=nsign_in /data/data/com.penti.app/files/adj9_capture.log'"],
                    capture_output=True, text=True, cwd="C:\\Users\\Apps\\Downloads\\com.penti.app")
print("total nsign_in:", r2.stdout.strip())
