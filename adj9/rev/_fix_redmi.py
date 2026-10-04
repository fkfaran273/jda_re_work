import io

t = io.open("py_redmi.py", encoding="utf-8").read()
old = '"hardware_name": "", "os_build"'
new = '"hardware_name": "S2SE32.28-28-4", "os_build"'
if old in t:
    t = t.replace(old, new)
    io.open("py_redmi.py", "w", encoding="utf-8").write(t)
    print("fixed empty hardware_name")
else:
    print("pattern not found")
