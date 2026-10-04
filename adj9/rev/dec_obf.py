import base64, re
# candidates of sig-sdk obfuscated strings
cands=["Y0D+Y0C+Y0R+Y0Q+","Y16+Y14+Y15+","YA6+YA4+YA5+","TxK+TyG+n0","+T1yOT2zOp0",
"7Y=7GO7V","7Y=7HO7V","76Z7N=78","7=g7rg7Ig7","7DR7Zl7+R7","7Kl7Dl7Y=7","7Ol78l7g=7",
"7Ol7Dl7Y=7","7Tk7Y=7GO7","7Tk7Y=7HO7","7Y=7Mk7qF7","7Y=7vj7Mk7","=7OH7NH7Mk7",
"j7Q=7qY7OW7jW7","TPwPTQvPRRxPRSsPTTuPrT","TPwPRRxPRSsPTTuPrT","Ta8UTb9UUc7UUd6U","xKKZKZKZKZKZKZKZK",
"Quoh8uafohgh7CahM2h"]
# Try common sig-sdk obfuscation: XOR with 0x69? ROT? First inspect char frequency:
for s in cands:
    print(s, "->", "".join(chr((ord(c)^0x69)&0xff) if 32<=(ord(c)^0x69)<127 else "." for c in s))
