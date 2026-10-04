"""_build_one_click.py — assemble one_click_run/adj9_signer.py from:
  header: _header.py (docstring + imports)
  core:   pure_sign.py's stdlib-only law (anchor-spliced: from "# PART 1"
          to "# __main__"), which now GENERATES the T and F tables from the
          AES formulas (T_LAW.md / F_LAW.md)
  footer: _footer.py (one-click API + self-test, @@GOLD@@ = the 9 frozen
          vectors produced by pure_signer/_dump_vectors.py)
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.dirname(HERE)
PURE = (r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/"
        "pure_signer/pure_sign.py")

src = open(PURE, encoding="utf-8").read()
i0 = src.index("# =======================================================================\n"
               "# PART 0 — CONSTANTS")
i1 = src.index("# =======================================================================\n"
               "# __main__")
core = src[i0:i1].rstrip("\n")   # the whole stdlib-only law, anchor-spliced
assert "def sign_pure" in core and "def build_record" in core
assert "record_consts_ok" not in core, "RE utils must stay in the gate"
assert "_derive_tables" in core, "generated SBOX/F tables missing"

header = open(os.path.join(HERE, "_header.py"), encoding="utf-8").read()
footer = open(os.path.join(HERE, "_footer.py"), encoding="utf-8").read()
vecs = json.load(open(os.path.join(HERE, "_vectors_tmp.json"),
                      encoding="utf-8"))
gold = json.dumps(vecs, separators=(",", ":"), sort_keys=True)
assert "\n" not in gold and "'''" not in gold
footer = footer.replace("@@GOLD@@", gold)

out = header.rstrip("\n") + "\n\n" + core + "\n\n\n" + footer
dst = os.path.join(RUN, "adj9_signer.py")
with open(dst, "w", encoding="utf-8", newline="\n") as fh:
    fh.write(out)
print("wrote %s (%d bytes, %d lines, %d gold vectors)"
      % (dst, len(out), out.count("\n") + 1, len(vecs)))
