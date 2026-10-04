import io

lines = io.open("region_synth.py", encoding="utf-8").readlines()

# find where the OLD code starts (the second docstring with 'region_synth.py - build')
cut = None
for i, l in enumerate(lines):
    if l.startswith('"""region_synth.py - build a STRUCTURALLY'):
        cut = i
        break

if cut:
    out = lines[:cut]
    io.open("region_synth.py", "w", encoding="utf-8").write("".join(out))
    print("stripped old code at line %d; kept %d lines" % (cut, len(out)))
else:
    print("no old code found")
