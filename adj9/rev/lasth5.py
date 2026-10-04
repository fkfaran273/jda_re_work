import subprocess, re, glob, os
r = subprocess.run(["adb", "shell", "/debug_ramdisk/su -c 'grep -a -A2 type=nsign_in /data/data/com.penti.app/files/adj9_capture.log | grep -a arg3_hex | tail -12'"],
                   capture_output=True, text=True, cwd="C:\\Users\\Apps\\Downloads\\com.penti.app")
Hs = re.findall(r"arg3_hex=([0-9a-f]{64})", r.stdout)
print(len(Hs), "H values")
# need cycle-3 era: get ts+H pairs instead
r2 = subprocess.run(["adb", "shell", "/debug_ramdisk/su -c 'grep -a type=nsign_in /data/data/com.penti.app/files/adj9_capture.log'"],
                    capture_output=True, text=True, cwd="C:\\Users\\Apps\\Downloads\\com.penti.app")
tss = re.findall(r"ts=(\d+)", r2.stdout)
print("nsign_in ts list:", tss[-12:])
open("hlist.txt", "w").write("\n".join(Hs[-12:]))
