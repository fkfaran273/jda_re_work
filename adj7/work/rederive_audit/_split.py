import os
src = open("rd_verify.py", encoding="utf-8").read()
marker = "# ---------------- run over rows ----------------------------------------"
core, runner = src.split(marker, 1)
open("rd_core.py", "w", encoding="utf-8").write(core)
hdr = '"""runner part of rd_verify (crypto core lives in rd_core)"""\n' \
      'import json, os, sys\n' \
      'sys.path.insert(0, r"C:\\Users\\Apps\\Downloads\\com.penti.app\\adj7")\n' \
      'sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n' \
      'from rd_core import *\n\n'
open("rd_verify.py", "w", encoding="utf-8").write(hdr + marker + runner)
print("split done")
