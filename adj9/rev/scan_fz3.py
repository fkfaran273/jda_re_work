import os, glob
Hs = [
    bytes.fromhex("eb53f83b00a176f6e09f5b59cdc90288af703cd89b805933f75245ad773f6e4e"),
    bytes.fromhex("2ff623c3a9b9d028004b5b9a75f6d839dac1765b8f9fb41a1410e238d1f7584f"),
    bytes.fromhex("a5c650365ab083c1202753709856c3e3d6ce7ee96ae9f0c9e8b739a41294a62a"),
]
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
print("total hits:", hits)
