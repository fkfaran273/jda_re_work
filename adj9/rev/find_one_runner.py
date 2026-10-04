import subprocess, sys, os
py = r'C:/Users/Apps/.workbuddy-ai/binaries/python/envs/default/Scripts/python.exe'
for i in range(1, 8):
    src = f'import runpy,sys; sys.argv=["x"]; runpy.run_path(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/find_one.py", run_name="__main__")'
    code = f'''
import sys
sys.argv = ["find_one", r"C:/Users/Apps/Downloads/com.penti.app/extracted/base/classes{i}.dex"]
exec(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/find_one.py", encoding="utf-8").read())
'''
    p = subprocess.Popen([py, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        out, _ = p.communicate(timeout=240)
    except subprocess.TimeoutExpired:
        p.kill(); out = "TIMEOUT classes%d" % i
    print(out)
