import io

p = r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun\run_fix1.py"
data = io.open(p, "rb").read()
a1 = b"'adj_gps_adid=' + gaid + r'\x01'"
b1 = b"'adj_gps_adid=' + gaid + r'\\1'"
a2 = b"'gps_adid=' + gaid + r'\x01'"
b2 = b"'gps_adid=' + gaid + r'\\1'"
assert data.count(a1) == 1 and data.count(a2) == 1, (data.count(a1), data.count(a2))
data = data.replace(a1, b1).replace(a2, b2)
io.open(p, "wb").write(data)
print("fixed backreference")
