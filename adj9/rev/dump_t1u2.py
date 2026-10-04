import os, sys
from loguru import logger
logger.remove()
from androguard.misc import AnalyzeDex
from androguard.core.dex import DEX as DEXcls

DEXP = r"C:\Users\Apps\Downloads\com.penti.app\extracted\base\classes3.dex"
OUT = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\sigsrc_t1_u2.txt"
sys.stdout.reconfigure(line_buffering=True)
NEEDLES = ("Mac;", "Hmac", "adj_verification", "nSign", "Signature",
           "getInstance", "doFinal", "secret", "Secret", "Key", "key")

try:
    from androguard.core.dex import DEX as DalvikVMFormat
except ImportError:
    from androguard.core.bytecodes.dvm import DalvikVMFormat

d = DalvikVMFormat(open(DEXP, "rb").read())
buf = []
for c in d.get_classes():
    cn = c.get_name()
    if not cn.startswith("Lcom/adjust/sdk/sig/"):
        continue
    if cn not in ("Lt1;", "Lu2;", "Lcom/adjust/sdk/sig/t1;",
                  "Lcom/adjust/sdk/sig/u2;"):
        continue
    buf.append(f"\n########## {cn} ##########")
    for m in c.get_methods():
        buf.append(f"\n----- method {m.get_name()} {m.get_descriptor()} flags={m.get_access_flags_string()}")
        code = m.get_code()
        if code is None:
            buf.append("  (no code)")
            continue
        for ins in code.get_bc().get_instructions():
            op = ins.get_name()
            out = ins.get_output()
            if any(n in out for n in NEEDLES) or "invoke" in op or "sput" in op or "const-string" in op:
                buf.append(f"  {op} {out}")
open(OUT, "w", encoding="utf-8").write("\n".join(buf))
print("written", OUT, len(buf), "lines")
print("\n".join(buf[:80]))
