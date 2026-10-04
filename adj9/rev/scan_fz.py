import os, glob
Hs = [
    bytes.fromhex("df15015de958482eca187bdf3a2d53b02b847803748dddc594aefa1e0598f6ae"),
    bytes.fromhex("190c7f604964048a02c081b5c494e12f7d8aac4ac06633a42098644ffaee53bd"),
    bytes.fromhex("e02d208f5781aa621cfbd4245cd791c6522923379c84f476e05d593aff150d93"),
]
files = glob.glob("..\\device\\fz2\\*.bin")
print(len(files), "dump files")
for f in files:
    try:
        d = open(f, "rb").read()
    except Exception as e:
        continue
    for i, h in enumerate(Hs):
        p = d.find(h)
        if p != -1:
            print("HIT H%d in %s off %d (file %d bytes)" % (i, os.path.basename(f), p, len(d)))
