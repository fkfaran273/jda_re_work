from androguard.core.dex import DEX
d=DEX(open("C:/Users/Apps/Downloads/com.penti.app/extracted/base/classes3.dex","rb").read())
for c in d.get_classes():
    if c.get_name().startswith("Lcom/adjust/sdk/sig/") or c.get_name()=="Lcom/adjust/sdk/AdjustSigner;":
        n=c.get_name()
        for m in c.get_methods():
            code=m.get_code()
            if not code: continue
            bc=code.get_bc()
            txt=[]
            for ins in bc.get_instructions():
                op=ins.get_name(); out=ins.get_output()
                txt.append("%s %s"%(op,out))
                if "nSign" in out or "nsign" in out.lower():
                    print("###",n,"->",m.get_name(),m.get_descriptor())
            # capture methods referencing SecretKeySpec/Cipher/putInt
            j="\n".join(txt)
            if any(k in j for k in ("SecretKeySpec","Ljavax/crypto/Cipher","putInt","compile","0123456789abcdef")):
                print("=== %s %s %s (len %d insns)"%(n,m.get_name(),m.get_descriptor(),len(txt)))
                for line in txt[:120]: print("   ",line)
