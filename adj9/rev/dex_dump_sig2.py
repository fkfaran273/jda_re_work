import logging
logging.disable(logging.CRITICAL)
from androguard.core.dex import DEX
d=DEX(open("C:/Users/Apps/Downloads/com.penti.app/extracted/base/classes3.dex","rb").read())
out=[]
for c in d.get_classes():
    n=c.get_name()
    if not n.startswith("Lcom/adjust/sdk/sig/"): continue
    for m in c.get_methods():
        code=m.get_code()
        if not code: continue
        txt=[]
        try:
            for ins in code.get_bc().get_instructions():
                txt.append("%s %s"%(ins.get_name(),ins.get_output()))
        except Exception as e:
            continue
        j="\n".join(txt)
        if "nSign" in j:
            out.append((n,m.get_name(),m.get_descriptor(),txt))
for n,name,desc,txt in out:
    print("###",n,name,desc,"insns:",len(txt))
    for line in txt: print("  ",line)
