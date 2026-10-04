import io
import uuid

t = io.open("py_redmi.py", encoding="utf-8").read()
fresh = str(uuid.uuid4())
old = "auid = 'f0c45077-addf-4bd7-9428-52ca51ecb9b9'"
new = "auid = '" + fresh + "'"
if old in t:
    t = t.replace(old, new)
    io.open("py_redmi.py", "w", encoding="utf-8").write(t)
    print("fresh auid:", fresh)
else:
    print("old auid not found; keys present:", "auid = " in t)
