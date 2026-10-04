import glob, os
Hs = [bytes.fromhex(l.strip()) for l in open("hlist.txt") if len(l.strip()) == 64]
print(len(Hs), "keys")
files = glob.glob("..\\device\\fz3\\*.bin")
print(len(files), "files")
hits = 0
for f in files:
    try:
        d = open(f, "rb").read()
    except Exception:
        continue
    for i, h in enumerate(Hs):
        p = d.find(h)
        if p != -1:
            print("HIT H%d in %s off %d" % (i, os.path.basename(f), p))
            hits += 1
print("total:", hits)
