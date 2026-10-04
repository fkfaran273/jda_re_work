import io

t = io.open("hyp_run2.py", encoding="utf-8").read()
t = t.replace("import hyp_lib as H", "import hyp_lib as H\nH.SERIAL = \"ZD2228MY3X\"")
io.open("hyp_run2_moto.py", "w", encoding="utf-8").write(t)
print("moto H9 variant written")
