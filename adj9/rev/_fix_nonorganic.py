import io

t = io.open("py_nonorganic.py", encoding="utf-8").read()
old = '''    r = adb("shell", "curl -s -o /dev/null -w '%%{http_code}' -L '%s' "
                     "-H 'User-Agent: Mozilla/5.0 (Linux; Android 12; moto g42)'" % url := link)'''
new = '''    r = adb("shell", "curl -s -o /dev/null -w '%%{http_code}' -L '%s' "
                     "-H 'User-Agent: Mozilla/5.0 (Linux; Android 12; moto g42)'" % link)'''
if old in t:
    t = t.replace(old, new)
    io.open("py_nonorganic.py", "w", encoding="utf-8").write(t)
    print("fixed")
else:
    print("pattern not found")