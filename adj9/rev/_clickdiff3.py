import re
real = ("KlcAG2cbAAsKSl1KVi0FGiJbDHMI65a54be6-9328-4c4f-aa2a-5f3a4707457d31jut9tib0eeps3.14.0"
        "2026-09-25T09:44:07.587Z+0530moto g42phoneproduction0b84f65d4-c074-4373-b21e-6beaafd6e4fe"
        "serviceS2SE32.28-28-42026-09-14T17:52:12.431Z+0530S2SE32.28-28-4android12com.penti.app"
        "utm_source=google-play&utm_medium=organicgoogle150000010install_referrer10"
        "12026-09-24T20:36:30.448Z+0530clickandroid5.7.0105.0.0")
ours = ("KlcAG2cbAAsKSl1KVi0FGiJbDHMIxxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx31jut9tib0eeps3.14.0"
        "2026-09-25T10:08:04.961Z+0530moto g42phoneproduction052f48449-5f78-41d6-81d8-6823d6f2d61b"
        "serviceS2SE32.28-28-42026-09-25T10:05:14.774Z+0530S2SE32.28-28-4android12com.penti.app"
        "utm_source=(not%20set)&utm_medium=(not%20set)google150000010install_referrer10"
        "12026-09-25T10:05:14.774Z+0530clickandroid5.7.0105.0.0")
print("real len", len(real), "ours len", len(ours), "DELTA", len(ours)-len(real))
allts = lambda s: re.findall(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z\+0530", s)
def referrer(s):
    return s.split("com.penti.app",1)[1].split("google1500000",1)[0]
print("\nREFERER  REAL:", repr(referrer(real)), "len", len(referrer(real)))
print("REFERER  OURS:", repr(referrer(ours)), "len", len(referrer(ours)))
print("ref len delta:", len(referrer(ours))-len(referrer(real)))
print("\nts REAL:", allts(real))
print("ts OURS:", allts(ours))
# referrer length difference is the likely source of the 4 bytes
print("\nIf we matched the real referrer, our len would be:", len(ours)-len(referrer(ours))+len(referrer(real)))
