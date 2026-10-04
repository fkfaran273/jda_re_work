import subprocess
r = subprocess.run(
    ["adb", "shell", "/debug_ramdisk/su -c 'grep -a -o -E arg3_hex=[0-9a-f]+ /data/data/com.penti.app/files/adj9_capture.log | tail -3'"],
    capture_output=True, text=True, cwd="C:\\Users\\Apps\\Downloads\\com.penti.app")
print("OUT:", r.stdout[-600:])
print("ERR:", r.stderr[-300:])
